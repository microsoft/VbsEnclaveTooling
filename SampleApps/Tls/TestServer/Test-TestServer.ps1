#requires -Version 7.0
param(
    [int]$Port = 9443
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$certDir = Join-Path $PSScriptRoot "test-certs"
& (Join-Path $PSScriptRoot "generate-test-certs.ps1") -OutDir $certDir

$outFile = Join-Path $env:TEMP "tls-sample-test-server-$Port.out"
$errFile = Join-Path $env:TEMP "tls-sample-test-server-$Port.err"
Remove-Item $outFile, $errFile -ErrorAction SilentlyContinue

$server = Start-Process `
    -FilePath (Get-Process -Id $PID).Path `
    -ArgumentList @(
        "-NoProfile",
        "-File", (Join-Path $PSScriptRoot "Start-TestServer.ps1"),
        "-RunInCurrentProcess",
        "-Address", "127.0.0.1",
        "-Port", $Port,
        "-CertificatePath", (Join-Path $certDir "server.pfx"),
        "-MaxConnections", "1") `
    -PassThru `
    -RedirectStandardOutput $outFile `
    -RedirectStandardError $errFile

try {
    # Wait for the server's readiness banner instead of a fixed sleep, and fail
    # closed if it never appears (or the server exits early).
    $ready = $false
    $deadline = (Get-Date).AddSeconds(15)
    while ((Get-Date) -lt $deadline) {
        if ((Test-Path $outFile) -and (Select-String -Path $outFile -Pattern "listening on" -Quiet)) {
            $ready = $true
            break
        }
        if ($server.HasExited) {
            throw "Server exited early: $(Get-Content $errFile -Raw -ErrorAction SilentlyContinue)"
        }
        Start-Sleep -Milliseconds 200
    }
    if (-not $ready) {
        throw "Server did not become ready within the timeout."
    }

    $serverCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
        (Join-Path $certDir "server-cert.pem"))
    $tcpClient = [System.Net.Sockets.TcpClient]::new()
    $sslStream = $null
    try {
        $tcpClient.Connect("127.0.0.1", $Port)
        $expectedThumbprint = $serverCertificate.Thumbprint
        $validationCallback = {
            param($sender, $certificate, $chain, $sslPolicyErrors)
            $presentedCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certificate)
            try {
                return [string]::Equals($presentedCertificate.Thumbprint, $expectedThumbprint, [System.StringComparison]::OrdinalIgnoreCase)
            } finally {
                $presentedCertificate.Dispose()
            }
        }
        $sslStream = [System.Net.Security.SslStream]::new($tcpClient.GetStream(), $false, $validationCallback)
        $sslStream.AuthenticateAsClient("localhost", $null, [System.Security.Authentication.SslProtocols]::Tls13, $false)
        if ($sslStream.SslProtocol -ne [System.Security.Authentication.SslProtocols]::Tls13) {
            throw "Expected TLS 1.3, got $($sslStream.SslProtocol)"
        }

        $requestBytes = [System.Text.Encoding]::ASCII.GetBytes("GET /secret-config HTTP/1.1`r`nHost: localhost`r`nConnection: close`r`n`r`n")
        $sslStream.Write($requestBytes, 0, $requestBytes.Length)
        $sslStream.Flush()

        $buffer = [byte[]]::new(4096)
        $responseBytes = [System.Collections.Generic.List[byte]]::new()
        while ($true) {
            $read = $sslStream.Read($buffer, 0, $buffer.Length)
            if ($read -eq 0) {
                break
            }
            for ($i = 0; $i -lt $read; $i++) {
                $responseBytes.Add($buffer[$i])
            }
        }

        $response = [System.Text.Encoding]::UTF8.GetString($responseBytes.ToArray())
        if (-not $response.Contains("sample-server-only-value")) {
            throw "Expected deterministic secret payload in response"
        }
    } finally {
        if ($sslStream) {
            $sslStream.Dispose()
        }
        $tcpClient.Dispose()
        $serverCertificate.Dispose()
    }

    Wait-Process -Id $server.Id -Timeout 10
    if ($server.ExitCode -ne 0) {
        throw "Server exited with code $($server.ExitCode): $(Get-Content $errFile -Raw -ErrorAction SilentlyContinue)"
    }

    Write-Host "TLS sample test server smoke test passed"
} finally {
    if (-not $server.HasExited) {
        Stop-Process -Id $server.Id -Force
    }
    Remove-Item $outFile, $errFile -ErrorAction SilentlyContinue
}
