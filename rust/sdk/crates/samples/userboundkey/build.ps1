# Build script for the User-Bound Key sample.
#
# This script builds and optionally signs the userboundkey sample enclave.
#
# Usage:
#   .\build.ps1                              # Debug build only
#   .\build.ps1 -Configuration release       # Release build only
#   .\build.ps1 -CertName "MyCert"           # Debug build + sign
#   .\build.ps1 -Clean                       # Clean and rebuild

param(
    [ValidateSet("debug", "release")]
    [string]$Configuration = "debug",
    
    [switch]$Clean,
    
    [string]$CertName
)

$errorActionPreference = "Stop"

# Locate shared scripts folder
. "$PSScriptRoot\..\..\..\..\scripts\get_common_paths.ps1"

Write-Host "`n=== User-Bound Key Sample Build ===" -ForegroundColor Cyan
Write-Host "Configuration: $Configuration"
if ($CertName) {
    Write-Host "Certificate: $CertName (will sign enclave)"
}

# Clean if requested
if ($Clean) {
    Write-Host "`nCleaning build artifacts..." -ForegroundColor Yellow
    cargo clean
}

# Build the sample workspace
Write-Host "`nBuilding sample..." -ForegroundColor Yellow
. "$scriptsDir\invoke_cargo_build.ps1" -Path $PSScriptRoot -Configuration $Configuration

# Sign enclave DLL if certificate is provided
if ($CertName) {
    Write-Host "`nSigning enclave DLL..." -ForegroundColor Yellow
    
    $signScript = Join-Path $scriptsDir "sign-enclave.ps1"
    $targetDir = if ($Configuration -eq "release") { "release" } else { "debug" }
    $targetPath = Join-Path $PSScriptRoot "target\$targetDir"
    
    $enclaveDlls = Get-ChildItem -Path $targetPath -Filter "*_enclave.dll" -ErrorAction SilentlyContinue
    
    if (-not $enclaveDlls) {
        Write-Host "No enclave DLLs found to sign." -ForegroundColor Yellow
    } else {
        foreach ($dll in $enclaveDlls) {
            Write-Host "Signing $($dll.Name)..." -ForegroundColor Gray
            & $signScript -DllPath $dll.FullName -CertName $CertName
            if ($LASTEXITCODE -ne 0) { throw "Failed to sign $($dll.Name)" }
        }
        Write-Host "Enclave signed." -ForegroundColor Green
    }
}

Write-Host "`n=== Sample Build Complete ===" -ForegroundColor Cyan
$targetDir = if ($Configuration -eq "release") { "release" } else { "debug" }
Write-Host "Output: $(Join-Path $PSScriptRoot "target\$targetDir")"
