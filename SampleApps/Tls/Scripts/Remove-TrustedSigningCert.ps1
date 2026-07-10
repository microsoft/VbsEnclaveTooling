param(
    [string]$CertName = "TlsSampleEnclaveCert",
    [switch]$RemoveSigningCertificate
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$subject = "CN=$CertName"

function Remove-CertificatesFromStore {
    param(
        [Parameter(Mandatory = $true)]
        [string]$StoreName,

        [Parameter(Mandatory = $true)]
        [string]$Subject
    )

    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
        $StoreName,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser)
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    try {
        $matches = @($store.Certificates | Where-Object { $_.Subject -eq $Subject })
        foreach ($cert in $matches) {
            $thumbprint = $cert.Thumbprint
            $store.Remove($cert)
            Write-Host "Removed certificate $thumbprint from Cert:\CurrentUser\$StoreName."
        }

        return $matches.Count
    } finally {
        $store.Close()
    }
}

$trustedCount = Remove-CertificatesFromStore -StoreName "Root" -Subject $subject

if ($trustedCount -eq 0) {
    Write-Host "No trusted root certificate found for $subject."
}

if ($RemoveSigningCertificate) {
    $signingCount = Remove-CertificatesFromStore -StoreName "My" -Subject $subject

    if ($signingCount -eq 0) {
        Write-Host "No signing certificate found for $subject."
    }
}
