param(
    [string]$CertName = "TlsSampleEnclaveCert"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$subject = "CN=$CertName"
$cert = Get-ChildItem Cert:\CurrentUser\My |
    Where-Object { $_.Subject -eq $subject } |
    Select-Object -First 1

if (-not $cert) {
    $cert = New-SelfSignedCertificate `
        -CertStoreLocation Cert:\CurrentUser\My `
        -DnsName $CertName `
        -KeyUsage DigitalSignature `
        -KeySpec Signature `
        -KeyLength 2048 `
        -KeyAlgorithm RSA `
        -HashAlgorithm SHA256 `
        -TextExtension "2.5.29.37={text}1.3.6.1.5.5.7.3.3,1.3.6.1.4.1.311.76.57.1.15,1.3.6.1.4.1.311.97.814040577.346743380.4783503.105532347"
}

$existingRoot = Get-ChildItem Cert:\CurrentUser\Root |
    Where-Object { $_.Thumbprint -eq $cert.Thumbprint } |
    Select-Object -First 1

if ($existingRoot) {
    Write-Host "Certificate is already trusted in Cert:\CurrentUser\Root:"
    $existingRoot | Select-Object Subject, Thumbprint, NotAfter
    return
}

$temporaryCertificatePath = Join-Path $env:TEMP "$CertName.cer"
Export-Certificate -Cert $cert -FilePath $temporaryCertificatePath -Force | Out-Null

try {
    Import-Certificate -FilePath $temporaryCertificatePath -CertStoreLocation Cert:\CurrentUser\Root | Out-Null
} finally {
    Remove-Item -Force $temporaryCertificatePath -ErrorAction SilentlyContinue
}

Write-Host "Trusted certificate in Cert:\CurrentUser\Root:"
$cert | Select-Object Subject, Thumbprint, NotAfter
