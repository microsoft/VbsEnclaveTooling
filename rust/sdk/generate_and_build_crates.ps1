# Complete build pipeline for the VBS Enclave SDK workspace.
#
# This script performs the full build process:
# 1. Generates EDL bindings for all SDK and sample crates
# 2. Compiles the entire workspace with Cargo
# 3. Optionally signs enclave DLLs for deployment
#
# Usage:
#   .\generate_and_build_crates.ps1                              # Debug build only
#   .\generate_and_build_crates.ps1 -Configuration release        # Release build only
#   .\generate_and_build_crates.ps1 -CertName "MyCert"            # Debug build + sign
#   .\generate_and_build_crates.ps1 -Configuration release -CertName "MyCert"  # Release + sign

param(
    [ValidateSet("debug", "release")]
    [string]$Configuration = "debug",
    
    [string]$CertName
)

$errorActionPreference = "Stop"

# Locate shared scripts folder
. "$PSScriptRoot\..\scripts\get_common_paths.ps1"

Write-Host "`n=== VBS Enclave SDK Build ===" -ForegroundColor Cyan
Write-Host "Configuration: $Configuration"
if ($CertName) {
    Write-Host "Certificate: $CertName (will sign enclaves)"
}

# Step 1: Generate EDL bindings for entire workspace (SDK + samples)
Write-Host "`nGenerating EDL bindings..." -ForegroundColor Yellow
. "$PSScriptRoot\generate_codegen_for_workspace.ps1"

# Step 2: Build the entire SDK workspace with Cargo
Write-Host "`nBuilding workspace..." -ForegroundColor Yellow
. "$scriptsDir\invoke_cargo_build.ps1" -Path $PSScriptRoot -Configuration $Configuration

# Step 3: Sign enclave DLLs if certificate is provided
if ($CertName) {
    Write-Host "`nSigning enclave DLLs..." -ForegroundColor Yellow
    
    $signScript = Join-Path $scriptsDir "sign-enclave.ps1"
    $targetDir = if ($Configuration -eq "release") { "release" } else { "debug" }
    $targetPath = Join-Path $PSScriptRoot "target\$targetDir"

    # Find all enclave DLLs (convention: *_enclave.dll)
    $enclaveDlls = Get-ChildItem -Path $targetPath -Filter "*_enclave.dll" -ErrorAction SilentlyContinue

    if ($enclaveDlls.Count -eq 0) {
        Write-Host "No enclave DLLs found to sign." -ForegroundColor Yellow
    } else {
        foreach ($dll in $enclaveDlls) {
            Write-Host "Signing $($dll.Name)..." -ForegroundColor Gray
            & $signScript -DllPath $dll.FullName -CertName $CertName
            if ($LASTEXITCODE -ne 0) { throw "Failed to sign $($dll.Name)" }
        }
        Write-Host "All enclaves signed." -ForegroundColor Green
    }
}

Write-Host "`n=== SDK Build Complete ===" -ForegroundColor Cyan
$targetDir = if ($Configuration -eq "release") { "release" } else { "debug" }
Write-Host "Output directory: $(Join-Path $PSScriptRoot "target\$targetDir")"
if (-not $CertName) {
    Write-Host ""
    Write-Host "Tip: Use -CertName to sign enclave DLLs after build." -ForegroundColor Gray
}