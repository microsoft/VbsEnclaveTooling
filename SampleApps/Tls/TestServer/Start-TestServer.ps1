param(
    [string]$Address = "127.0.0.1",
    [int]$Port = 8443,
    [string]$CertificatePath = (Join-Path $PSScriptRoot "test-certs\server.pfx"),
    [string]$CertificateKeyPath = (Join-Path $PSScriptRoot "test-certs\server-key.pem"),
    [switch]$RequireClientCertificate,
    [string]$ClientCertificatePath = (Join-Path $PSScriptRoot "test-certs\client-cert.pem"),
    [int]$MaxConnections = 0,
    [switch]$RunInCurrentProcess
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not $RunInCurrentProcess) {
    $arguments = @(
        "-NoProfile",
        "-NoExit",
        "-File", $PSCommandPath,
        "-RunInCurrentProcess",
        "-Address", $Address,
        "-Port", $Port,
        "-CertificatePath", ([System.IO.Path]::GetFullPath($CertificatePath)),
        "-CertificateKeyPath", ([System.IO.Path]::GetFullPath($CertificateKeyPath)),
        "-ClientCertificatePath", ([System.IO.Path]::GetFullPath($ClientCertificatePath)),
        "-MaxConnections", $MaxConnections
    )
    if ($RequireClientCertificate) {
        $arguments += "-RequireClientCertificate"
    }

    $process = Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList $arguments -WorkingDirectory (Get-Location) -PassThru
    Write-Host "Started TLS sample test server in a new PowerShell window (PID $($process.Id))."
    return
}

$secretConfig = '{"operation":"scale-if-even","multiplier":37,"secretLabel":"sample-server-only-value"}'

function Get-HttpResponse {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    switch ($Path) {
        "/health" {
            return New-HttpResponse -Status "200 OK" -ContentType "text/plain" -Body "ok`n"
        }
        "/secret-config" {
            return New-HttpResponse -Status "200 OK" -ContentType "application/json" -Body $secretConfig
        }
        default {
            return New-HttpResponse -Status "404 Not Found" -ContentType "text/plain" -Body "not found`n"
        }
    }
}

function New-HttpResponse {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Status,

        [Parameter(Mandatory = $true)]
        [string]$ContentType,

        [Parameter(Mandatory = $true)]
        [string]$Body
    )

    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($Body)
    $headers = "HTTP/1.1 $Status`r`nContent-Type: $ContentType`r`nContent-Length: $($bodyBytes.Length)`r`nConnection: close`r`n`r`n"
    $headerBytes = [System.Text.Encoding]::ASCII.GetBytes($headers)
    $response = [byte[]]::new($headerBytes.Length + $bodyBytes.Length)
    [System.Buffer]::BlockCopy($headerBytes, 0, $response, 0, $headerBytes.Length)
    [System.Buffer]::BlockCopy($bodyBytes, 0, $response, $headerBytes.Length, $bodyBytes.Length)
    return $response
}

function Get-RequestPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Request
    )

    $requestLine = ($Request -split "`r?`n", 2)[0]
    $parts = $requestLine -split " "
    if (($parts.Count -ne 3) -or ($parts[0] -ne "GET") -or (-not $parts[2].StartsWith("HTTP/"))) {
        return $null
    }

    return $parts[1]
}

function Read-HttpRequest {
    param(
        [Parameter(Mandatory = $true)]
        [System.Net.Security.SslStream]$Stream
    )

    $buffer = [byte[]]::new(1024)
    $request = [System.Collections.Generic.List[byte]]::new()
    while ($true) {
        $read = $Stream.Read($buffer, 0, $buffer.Length)
        if ($read -eq 0) {
            break
        }

        for ($i = 0; $i -lt $read; $i++) {
            $request.Add($buffer[$i])
        }

        if ($request.Count -gt (16 * 1024)) {
            throw "request headers too large"
        }

        $requestText = [System.Text.Encoding]::ASCII.GetString($request.ToArray())
        if ($requestText.Contains("`r`n`r`n")) {
            return $requestText
        }
    }

    return [System.Text.Encoding]::ASCII.GetString($request.ToArray())
}

function Get-CertificateThumbprint {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($Path)
    try {
        return $certificate.Thumbprint
    } finally {
        $certificate.Dispose()
    }
}

function Get-CertificateSha256 {
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    $hash = [System.Security.Cryptography.SHA256]::HashData($Certificate.RawData)
    return [System.BitConverter]::ToString($hash).Replace("-", "").ToLowerInvariant()
}

function Get-ServerCertificate {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$KeyPath
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $fullKeyPath = [System.IO.Path]::GetFullPath($KeyPath)

    if ([System.IO.Path]::GetExtension($fullPath).Equals(".pem", [System.StringComparison]::OrdinalIgnoreCase)) {
        $pemCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPemFile($fullPath, $fullKeyPath)
        try {
            $pfxBytes = $pemCertificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12)
            return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
                $pfxBytes,
                "",
                [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::UserKeySet)
        } finally {
            $pemCertificate.Dispose()
        }
    }

    $certDirectory = Split-Path -Parent $fullPath
    $siblingPem = Join-Path $certDirectory "server-cert.pem"
    $siblingKey = Join-Path $certDirectory "server-key.pem"
    if ((Test-Path $siblingPem) -and (Test-Path $siblingKey)) {
        return Get-ServerCertificate -Path $siblingPem -KeyPath $siblingKey
    }

    return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($fullPath)
}

function Invoke-ClientValidation {
    param(
        [object]$Certificate,
        [string]$ExpectedThumbprint
    )

    if ($null -eq $Certificate) {
        return $false
    }

    $presentedCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($Certificate)
    try {
        return [string]::Equals($presentedCertificate.Thumbprint, $ExpectedThumbprint, [System.StringComparison]::OrdinalIgnoreCase)
    } finally {
        $presentedCertificate.Dispose()
    }
}

function Invoke-Connection {
    param(
        [Parameter(Mandatory = $true)]
        [System.Net.Sockets.TcpClient]$Client,

        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$ServerCertificate,

        [string]$ExpectedClientThumbprint
    )

    $sslStream = $null
    try {
        $networkStream = $Client.GetStream()
        if ($ExpectedClientThumbprint) {
            $validationCallback = {
                param($sender, $certificate, $chain, $sslPolicyErrors)
                Invoke-ClientValidation -Certificate $certificate -ExpectedThumbprint $ExpectedClientThumbprint
            }
            $sslStream = [System.Net.Security.SslStream]::new($networkStream, $false, $validationCallback)
        } else {
            $sslStream = [System.Net.Security.SslStream]::new($networkStream, $false)
        }

        $options = [System.Net.Security.SslServerAuthenticationOptions]::new()
        $options.ServerCertificate = $ServerCertificate
        $options.EnabledSslProtocols = [System.Security.Authentication.SslProtocols]::Tls13
        $options.ClientCertificateRequired = [bool]$ExpectedClientThumbprint
        $options.ApplicationProtocols = [System.Collections.Generic.List[System.Net.Security.SslApplicationProtocol]]::new()
        $options.ApplicationProtocols.Add([System.Net.Security.SslApplicationProtocol]::Http11)
        $sslStream.AuthenticateAsServer($options)

        $request = Read-HttpRequest -Stream $sslStream
        $path = Get-RequestPath -Request $request
        if (-not $path) {
            $path = "/"
        }

        Write-Host ("peer={0} version={1} cipher={2} alpn={3} client_cert={4}" -f
            $Client.Client.RemoteEndPoint,
            $sslStream.SslProtocol,
            $sslStream.NegotiatedCipherSuite,
            $sslStream.NegotiatedApplicationProtocol,
            [bool]$sslStream.RemoteCertificate)

        $response = Get-HttpResponse -Path $path
        $sslStream.Write($response, 0, $response.Length)
        $sslStream.Flush()
    } finally {
        if ($sslStream) {
            $sslStream.Dispose()
        }
        $Client.Dispose()
    }
}

$serverCertificate = Get-ServerCertificate -Path $CertificatePath -KeyPath $CertificateKeyPath
$expectedClientThumbprint = $null
if ($RequireClientCertificate) {
    $expectedClientThumbprint = Get-CertificateThumbprint -Path $ClientCertificatePath
}

$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse($Address), $Port)
$acceptedConnections = 0

try {
    $listener.Start()
    Write-Host "TLS sample test server listening on $Address`:$Port"
    Write-Host "server_cert_sha256=$(Get-CertificateSha256 -Certificate $serverCertificate)"

    while (($MaxConnections -eq 0) -or ($acceptedConnections -lt $MaxConnections)) {
        $client = $listener.AcceptTcpClient()
        $acceptedConnections++
        try {
            Invoke-Connection -Client $client -ServerCertificate $serverCertificate -ExpectedClientThumbprint $expectedClientThumbprint
        } catch {
            Write-Error -ErrorAction Continue $_
        }
    }
} finally {
    $listener.Stop()
    $serverCertificate.Dispose()
}
