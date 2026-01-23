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

# Read the installation folder
$sdk = Get-ItemProperty -Path $sdkRegPath
$installationFolder = $sdk.InstallationFolder

Write-Host "`nAttempting to run veiid.exe and sign enclave DLL using certificate '$CertName'..."

if (-not $installationFolder) {
    throw "Incomplete Windows SDK installation. Please reinstall the latest Windows SDK."
}

# Find an SDK version that has veiid.exe in its bin folder
# List all version folders under bin and find one with veiid.exe
$binRoot = Join-Path $installationFolder "bin"
if (-not (Test-Path $binRoot)) {
    throw "Windows SDK bin folder not found at: $binRoot. Please install the latest Windows SDK."
}

$sdkBin = $null
$versionFolders = Get-ChildItem -Path $binRoot -Directory | Sort-Object Name -Descending
foreach ($versionFolder in $versionFolders) {
    $candidateBin = Join-Path $versionFolder.FullName "x64"
    $candidateVeiid = Join-Path $candidateBin "veiid.exe"
    if (Test-Path $candidateVeiid) {
        $sdkBin = $candidateBin
        Write-Host "Found SDK tools in: $sdkBin"
        break
    }
}

if (-not $sdkBin) {
    throw "Could not find veiid.exe in any SDK version under $binRoot. Please install Windows SDK 10.0.26100.0 or higher."
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
# There is a bug in signtool where even though it signs the enclave correctly
# it returns a non zero exit code for warnings and outputs:
# SignTool Warning: Note that VBS enclave support is changing and updating your
# VBS enclave may cause you to lose support on older OSes
# So we will say the signing failed if the signtool returns 0 or 2.
if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 2) {
    Write-Host "signtool signing failed."
    throw "signtool signing failed with exit code $LASTEXITCODE"
}

if ($LASTEXITCODE -ne 0) {
    Write-Host "Enclave DLL signing completed with warnings (exit code $LASTEXITCODE)."
} else {
    Write-Host "Enclave DLL signing completed with no warnings."
}

# Exit with success since signing completed (even with warnings)
exit 0