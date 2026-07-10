param(
    [string]$OutDir = (Join-Path $PSScriptRoot "test-certs")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Add-Type -AssemblyName System.Security

$OutDir = [System.IO.Path]::GetFullPath($OutDir)

function New-SampleCertificate {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CommonName,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$EnhancedKeyUsageOid,

        [string[]]$DnsNames = @(),

        [string[]]$IpAddresses = @()
    )

    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $distinguishedName = [System.Security.Cryptography.X509Certificates.X500DistinguishedName]::new("CN=$CommonName")
    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        $distinguishedName,
        $rsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)

    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false, $false, 0, $true))
    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
            [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature,
            $true))
    $enhancedKeyUsage = [System.Security.Cryptography.OidCollection]::new()
    [void]$enhancedKeyUsage.Add([System.Security.Cryptography.Oid]::new($EnhancedKeyUsageOid))
    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new(
            $enhancedKeyUsage,
            $true))

    if (($DnsNames.Count -gt 0) -or ($IpAddresses.Count -gt 0)) {
        $sanBuilder = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
        foreach ($dnsName in $DnsNames) {
            $sanBuilder.AddDnsName($dnsName)
        }
        foreach ($ipAddress in $IpAddresses) {
            $sanBuilder.AddIpAddress([System.Net.IPAddress]::Parse($ipAddress))
        }
        $request.CertificateExtensions.Add($sanBuilder.Build())
    }

    $notBefore = [System.DateTimeOffset]::UtcNow.AddDays(-1)
    $notAfter = $notBefore.AddYears(2)
    $certificate = $request.CreateSelfSigned($notBefore, $notAfter)

    [System.IO.File]::WriteAllText(
        (Join-Path $OutDir "$Name-cert.pem"),
        $certificate.ExportCertificatePem())
    [System.IO.File]::WriteAllText(
        (Join-Path $OutDir "$Name-key.pem"),
        $rsa.ExportPkcs8PrivateKeyPem())
    [System.IO.File]::WriteAllBytes(
        (Join-Path $OutDir "$Name.pfx"),
        $certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12))

    $certificate.Dispose()
    $rsa.Dispose()
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

New-SampleCertificate `
    -CommonName "localhost" `
    -Name "server" `
    -EnhancedKeyUsageOid "1.3.6.1.5.5.7.3.1" `
    -DnsNames @("localhost") `
    -IpAddresses @("127.0.0.1")

New-SampleCertificate `
    -CommonName "tls-sample-client" `
    -Name "client" `
    -EnhancedKeyUsageOid "1.3.6.1.5.5.7.3.2"

Write-Host "Wrote TLS sample certificates to $OutDir"
