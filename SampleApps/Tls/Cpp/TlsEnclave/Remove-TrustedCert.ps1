param(
    [string]$CertName = "TlsSampleEnclaveCert",
    [switch]$RemoveSigningCertificate
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$subject = "CN=$CertName"

$trustedCertificates = @(Get-ChildItem Cert:\CurrentUser\Root |
    Where-Object { $_.Subject -eq $subject })

foreach ($cert in $trustedCertificates) {
    Remove-Item -Path ("Cert:\CurrentUser\Root\{0}" -f $cert.Thumbprint) -Force
    Write-Host "Removed trusted root certificate $($cert.Thumbprint)."
}

if ($trustedCertificates.Count -eq 0) {
    Write-Host "No trusted root certificate found for $subject."
}

if ($RemoveSigningCertificate) {
    $signingCertificates = @(Get-ChildItem Cert:\CurrentUser\My |
        Where-Object { $_.Subject -eq $subject })

    foreach ($cert in $signingCertificates) {
        Remove-Item -Path ("Cert:\CurrentUser\My\{0}" -f $cert.Thumbprint) -Force
        Write-Host "Removed signing certificate $($cert.Thumbprint)."
    }

    if ($signingCertificates.Count -eq 0) {
        Write-Host "No signing certificate found for $subject."
    }
}
