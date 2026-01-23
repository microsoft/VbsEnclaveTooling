# Complete build pipeline for the VBS Enclave SDK workspace.
#
# This script performs the full build process:
# 1. Generates EDL bindings for all SDK and sample crates
# 2. Compiles the SDK workspace with Cargo
# 3. Compiles sample workspaces separately
# 4. Optionally signs enclave DLLs for deployment
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

# Step 1: Generate EDL bindings for SDK and samples
Write-Host "`nGenerating EDL bindings..." -ForegroundColor Yellow
. "$PSScriptRoot\generate_codegen_for_workspace.ps1"

# Step 2: Build the SDK workspace with Cargo
Write-Host "`nBuilding SDK workspace..." -ForegroundColor Yellow
. "$scriptsDir\invoke_cargo_build.ps1" -Path $PSScriptRoot -Configuration $Configuration

# Step 3: Build sample workspaces separately
# Samples are in their own workspaces to allow different panic profiles
# (enclave uses panic=abort, host uses default panic=unwind)
Write-Host "`nBuilding sample workspaces..." -ForegroundColor Yellow

$sampleWorkspaces = @(
    (Join-Path $PSScriptRoot "crates\samples\userboundkey")
)

foreach ($samplePath in $sampleWorkspaces) {
    if (Test-Path (Join-Path $samplePath "Cargo.toml")) {
        Write-Host "Building sample: $(Split-Path $samplePath -Leaf)" -ForegroundColor Gray
        . "$scriptsDir\invoke_cargo_build.ps1" -Path $samplePath -Configuration $Configuration
    }
}

# Step 4: Sign enclave DLLs if certificate is provided
if ($CertName) {
    Write-Host "`nSigning enclave DLLs..." -ForegroundColor Yellow
    
    $signScript = Join-Path $scriptsDir "sign-enclave.ps1"
    $targetDir = if ($Configuration -eq "release") { "release" } else { "debug" }
    
    # Collect enclave DLLs from SDK and sample target directories
    $targetPaths = @(
        (Join-Path $PSScriptRoot "target\$targetDir")
    )
    foreach ($samplePath in $sampleWorkspaces) {
        $targetPaths += (Join-Path $samplePath "target\$targetDir")
    }

    $enclaveDlls = @()
    foreach ($targetPath in $targetPaths) {
        $dlls = Get-ChildItem -Path $targetPath -Filter "*_enclave.dll" -ErrorAction SilentlyContinue
        if ($dlls) { $enclaveDlls += $dlls }
    }

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
Write-Host "SDK output: $(Join-Path $PSScriptRoot "target\$targetDir")"
Write-Host "Sample output: $(Join-Path $PSScriptRoot "crates\samples\userboundkey\target\$targetDir")"
if (-not $CertName) {
    Write-Host ""
    Write-Host "Tip: Use -CertName to sign enclave DLLs after build." -ForegroundColor Gray
}