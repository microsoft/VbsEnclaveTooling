# Generates enclave identity using veiid.exe and signs the DLL with
# signtool when a certificate name is supplied.

param(
    [Parameter(Mandatory=$true)]
    [string]$DllPath,

    [string]$CertName = ""
)
$ErrorActionPreference = "Stop"

if ($CertName -eq "") {
    Write-Host "`nSkipping enclave dll signing (no certificate name supplied)."
    exit 0
}

# Windows SDK registry key path
$sdkRegPath = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Microsoft SDKs\Windows\v10.0"

# Verify the key exists
if (-not (Test-Path $sdkRegPath)) {
    throw "Windows SDK not found. Please install the latest Windows 11 SDK."
}

# Read the two important values
$sdk = Get-ItemProperty -Path $sdkRegPath

$installationFolder = $sdk.InstallationFolder
$productVersion     = $sdk.ProductVersion

Write-Host "`nAttempting to run veiid.exe and sign enclave DLL using certificate '$CertName'..."

if (-not $installationFolder -or -not $productVersion) {
    throw "Incomplete Windows SDK installation. Please reinstall the latest Windows SDK."
}

# Build full SDK bin path
$sdkBin = Join-Path $installationFolder "bin\$productVersion.0\x64"

if (-not (Test-Path $sdkBin)) {
    throw "Windows SDK bin folder not found at: $sdkBin. Please install (or repair) the latest Windows SDK."
}

# Compute tool paths
$veiidPath   = Join-Path $sdkBin "veiid.exe"
$signToolPath = Join-Path $sdkBin "signtool.exe"

if (-not (Test-Path $veiidPath)) {
    throw "veiid.exe not found in SDK. Install the latest Windows SDK."
}

if (-not (Test-Path $signToolPath)) {
    throw "signtool.exe not found in SDK. Install the latest Windows SDK."
}

if (-not (Test-Path $DllPath)) {
    throw "Could not find enclave DLL at: $DllPath"
}

Write-Host "Running veiid.exe..."
& $veiidPath $DllPath
if ($LASTEXITCODE -ne 0) {
    throw "veiid.exe failed with exit code $LASTEXITCODE"
}

Write-Host "veiid.exe completed successfully."

Write-Host "Signing DLL with signtool..."
& $signToolPath sign /ph /a /fd SHA256 /r $CertName $DllPath

# Check for errors (non-zero exit code) or warning (exit code 2)
if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 2) {
    Write-Host "signtool signing failed."
    throw "signtool signing failed with exit code $LASTEXITCODE"
}

Write-Host "`nEnclave DLL successfully signed."