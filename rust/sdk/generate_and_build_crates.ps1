# Complete build pipeline for the VBS Enclave SDK workspace.
#
# This script performs the full build process:
# 1. Generates EDL bindings for all SDK and sample crates
# 2. Compiles the SDK workspace with Cargo
# 3. Optionally compiles sample workspaces (use -IncludeSamples)
# 4. Optionally signs enclave DLLs for deployment
#
# Usage:
#   .\generate_and_build_crates.ps1                              # Debug build (SDK only)
#   .\generate_and_build_crates.ps1 -IncludeSamples              # Debug build + samples
#   .\generate_and_build_crates.ps1 -Configuration release       # Release build (SDK only)
#   .\generate_and_build_crates.ps1 -CertName "MyCert"           # Debug build + sign
#   .\generate_and_build_crates.ps1 -IncludeSamples -CertName "MyCert"  # Full build + sign

param(
    [ValidateSet("debug", "release")]
    [string]$Configuration = "debug",
    
    [switch]$IncludeSamples,
    
    [string]$CertName
)

$errorActionPreference = "Stop"

# Locate shared scripts folder
. "$PSScriptRoot\..\scripts\get_common_paths.ps1"

Write-Host "`n=== VBS Enclave SDK Build ===" -ForegroundColor Cyan
Write-Host "Configuration: $Configuration"
if ($IncludeSamples) {
    Write-Host "Samples: Included"
}
if ($CertName) {
    Write-Host "Certificate: $CertName (will sign enclaves)"
}

# Step 1: Generate EDL bindings for SDK and samples
Write-Host "`nGenerating EDL bindings..." -ForegroundColor Yellow
. "$PSScriptRoot\generate_codegen_for_workspace.ps1"

# Step 2: Build the SDK workspace with Cargo
Write-Host "`nBuilding SDK workspace..." -ForegroundColor Yellow
. "$scriptsDir\invoke_cargo_build.ps1" -Path $PSScriptRoot -Configuration $Configuration

# Step 3: Sign SDK enclave DLLs if certificate is provided
if ($CertName) {
    Write-Host "`nSigning SDK enclave DLLs..." -ForegroundColor Yellow
    
    $signScript = Join-Path $scriptsDir "sign-enclave.ps1"
    $targetDir = if ($Configuration -eq "release") { "release" } else { "debug" }
    $targetPath = Join-Path $PSScriptRoot "target\$targetDir"
    
    $enclaveDlls = Get-ChildItem -Path $targetPath -Filter "*_enclave.dll" -ErrorAction SilentlyContinue
    
    if (-not $enclaveDlls) {
        Write-Host "No SDK enclave DLLs found to sign." -ForegroundColor Yellow
    } else {
        foreach ($dll in $enclaveDlls) {
            Write-Host "Signing $($dll.Name)..." -ForegroundColor Gray
            & $signScript -DllPath $dll.FullName -CertName $CertName
            if ($LASTEXITCODE -ne 0) { throw "Failed to sign $($dll.Name)" }
        }
        Write-Host "SDK enclaves signed." -ForegroundColor Green
    }
}

# Step 4: Build samples (only if -IncludeSamples is specified)
# Each sample has its own build.ps1 script that handles building and signing
$sampleScripts = @(
    (Join-Path $PSScriptRoot "crates\samples\userboundkey\build.ps1")
)

if ($IncludeSamples) {
    Write-Host "`nBuilding samples..." -ForegroundColor Yellow

    foreach ($sampleScript in $sampleScripts) {
        if (Test-Path $sampleScript) {
            $sampleName = Split-Path (Split-Path $sampleScript -Parent) -Leaf
            Write-Host "Building sample: $sampleName" -ForegroundColor Gray
            
            if ($CertName) {
                & $sampleScript -Configuration $Configuration -CertName $CertName
            } else {
                & $sampleScript -Configuration $Configuration
            }
            if ($LASTEXITCODE -ne 0) { throw "Failed to build sample: $sampleName" }
        }
    }
}

Write-Host "`n=== SDK Build Complete ===" -ForegroundColor Cyan
$targetDir = if ($Configuration -eq "release") { "release" } else { "debug" }
Write-Host "SDK output: $(Join-Path $PSScriptRoot "target\$targetDir")"
if ($IncludeSamples) {
    Write-Host "Sample output: $(Join-Path $PSScriptRoot "crates\samples\userboundkey\target\$targetDir")"
}
if (-not $CertName) {
    Write-Host ""
    Write-Host "Tip: Use -CertName to sign enclave DLLs after build." -ForegroundColor Gray
}
if (-not $IncludeSamples) {
    Write-Host "Tip: Use -IncludeSamples to also build sample applications." -ForegroundColor Gray
}