# Builds and signs the userboundkey sample.
#
# Usage:
#   .\build.ps1 -CertName "MyTestEnclaveCertNew"
#   .\build.ps1 -CertName "MyTestEnclaveCertNew" -Configuration Release

param(
    [Parameter(Mandatory=$true)]
    [string]$CertName,

    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug"
)

$ErrorActionPreference = "Stop"

$sampleDir = $PSScriptRoot
$sdkRoot = Resolve-Path "$sampleDir\..\..\..\"
$rustRoot = Resolve-Path "$sdkRoot\.."
$scriptsDir = Join-Path $rustRoot "scripts"

Write-Host "`n=== User-Bound Key Sample Build ===" -ForegroundColor Cyan
Write-Host "Configuration: $Configuration"
Write-Host "Certificate: $CertName"

# ============================================================================
# Step 1: Generate EDL bindings
# ============================================================================
Write-Host "`n[1/3] Generating EDL bindings..." -ForegroundColor Yellow

$generateScript = Join-Path $scriptsDir "generate_codegen_crates.ps1"
$sampleEdl = Join-Path $sampleDir "userboundkey_sample.edl"
$libsImportDir = Join-Path $sdkRoot "crates\libs"

& $generateScript `
    -HostAppOutDir "$sampleDir\host\generated" `
    -EnclaveOutDir "$sampleDir\enclave\generated" `
    -EdlPath $sampleEdl `
    -Namespace "userboundkey_sample" `
    -Vtl0ClassName "userboundkey_sampleWrapper" `
    -ImportDirectories $libsImportDir

if ($LASTEXITCODE -ne 0) { throw "EDL generation failed." }
Write-Host "EDL bindings generated." -ForegroundColor Green

# ============================================================================
# Step 2: Build host and enclave
# ============================================================================
Write-Host "`n[2/3] Building..." -ForegroundColor Yellow

Push-Location $sdkRoot
try {
    $buildArgs = @("build", "-p", "userboundkey-sample-host", "-p", "userboundkey-sample-enclave")
    if ($Configuration -eq "Release") {
        $buildArgs += "--release"
    }
    
    cargo @buildArgs
    
    if ($LASTEXITCODE -ne 0) { throw "Cargo build failed." }
} finally {
    Pop-Location
}
Write-Host "Build completed." -ForegroundColor Green

# ============================================================================
# Step 3: Sign the enclave
# ============================================================================
Write-Host "`n[3/3] Signing enclave..." -ForegroundColor Yellow

$targetDir = if ($Configuration -eq "Release") { "release" } else { "debug" }
$enclaveDll = Join-Path $sdkRoot "target\$targetDir\userboundkey_sample_enclave.dll"
$signScript = Join-Path $scriptsDir "sign-enclave.ps1"

& $signScript -DllPath $enclaveDll -CertName $CertName

if ($LASTEXITCODE -ne 0) { throw "Signing failed." }
Write-Host "Enclave signed." -ForegroundColor Green

# ============================================================================
# Done
# ============================================================================
Write-Host "`n=== Build Complete ===" -ForegroundColor Cyan
Write-Host "Output: $(Join-Path $sdkRoot "target\$targetDir")"
Write-Host ""
Write-Host "To run:"
Write-Host "  cd $(Join-Path $sdkRoot "target\$targetDir")"
Write-Host "  .\userboundkey-sample.exe"
