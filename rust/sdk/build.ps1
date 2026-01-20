# Generates EDL bindings and builds the entire SDK workspace.
#
# Usage:
#   .\build.ps1                                              # Debug build
#   .\build.ps1 -Configuration Release                       # Release build
#   .\build.ps1 -CertName "MyCert"                           # Debug build + sign enclaves
#   .\build.ps1 -Configuration Release -CertName "MyCert"    # Release build + sign enclaves

param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug",

    [string]$CertName
)

$ErrorActionPreference = "Stop"

$sdkRoot = $PSScriptRoot
$rustRoot = Resolve-Path "$sdkRoot\.."
$repoRoot = Resolve-Path "$rustRoot\.."
$scriptsDir = Join-Path $rustRoot "scripts"

Write-Host "`n=== VBS Enclave SDK Build Script ===" -ForegroundColor Cyan
Write-Host "Configuration: $Configuration"
if ($CertName) {
    Write-Host "Certificate: $CertName (will sign enclaves)"
}

$totalSteps = if ($CertName) { 4 } else { 3 }

# ============================================================================
# Step 1: Generate SDK EDL bindings
# ============================================================================
Write-Host "`n[1/$totalSteps] Generating SDK EDL bindings..." -ForegroundColor Yellow

$generateScript = Join-Path $scriptsDir "generate_codegen_crates.ps1"

# SDK crate paths
$enclaveSdkCrate = Join-Path $sdkRoot "crates\libs\sdk-enclave"
$hostSdkCrate = Join-Path $sdkRoot "crates\libs\sdk-host"

# Generate veil_abi EDL bindings
$veilAbiEdl = Join-Path $repoRoot "src\VbsEnclaveSDK\veil_abi.edl"
& $generateScript `
    -HostAppOutDir "$hostSdkCrate\generated" `
    -EnclaveOutDir "$enclaveSdkCrate\generated" `
    -EdlPath $veilAbiEdl `
    -Namespace "veil_abi" `
    -Vtl0ClassName "export_interface"

if ($LASTEXITCODE -ne 0) { throw "veil_abi EDL generation failed." }

# Generate userboundkey EDL bindings  
$userboundkeyEdl = Join-Path $sdkRoot "crates\libs\userboundkey.edl"
& $generateScript `
    -HostAppOutDir "$hostSdkCrate\generated" `
    -EnclaveOutDir "$enclaveSdkCrate\generated" `
    -EdlPath $userboundkeyEdl `
    -Namespace "userboundkey" `
    -Vtl0ClassName "UserBoundKeyVtl0Host"

if ($LASTEXITCODE -ne 0) { throw "userboundkey EDL generation failed." }

Write-Host "SDK EDL bindings generated." -ForegroundColor Green

# ============================================================================
# Step 2: Generate sample EDL bindings
# ============================================================================
Write-Host "`n[2/$totalSteps] Generating sample EDL bindings..." -ForegroundColor Yellow

# Userboundkey sample
$sampleDir = Join-Path $sdkRoot "crates\samples\userboundkey"
$sampleEdl = Join-Path $sampleDir "userboundkey_sample.edl"
$libsImportDir = Join-Path $sdkRoot "crates\libs"

& $generateScript `
    -HostAppOutDir "$sampleDir\host\generated" `
    -EnclaveOutDir "$sampleDir\enclave\generated" `
    -EdlPath $sampleEdl `
    -Namespace "userboundkey_sample" `
    -Vtl0ClassName "userboundkey_sampleWrapper" `
    -ImportDirectories $libsImportDir

if ($LASTEXITCODE -ne 0) { throw "userboundkey_sample EDL generation failed." }

Write-Host "Sample EDL bindings generated." -ForegroundColor Green

# ============================================================================
# Step 3: Format and build workspace
# ============================================================================
Write-Host "`n[3/$totalSteps] Building workspace..." -ForegroundColor Yellow

# Format generated code
$formatScript = Join-Path $scriptsDir "invoke_rustfmt_workspace.ps1"
& $formatScript -WorkspacePath $sdkRoot

# Build workspace
Push-Location $sdkRoot
try {
    $buildArgs = @("build", "--workspace")
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
# Step 4: Sign enclaves (optional)
# ============================================================================
if ($CertName) {
    Write-Host "`n[4/$totalSteps] Signing enclave DLLs..." -ForegroundColor Yellow

    $signScript = Join-Path $scriptsDir "sign-enclave.ps1"
    $targetDir = if ($Configuration -eq "Release") { "release" } else { "debug" }
    $targetPath = Join-Path $sdkRoot "target\$targetDir"

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
$targetDir = if ($Configuration -eq "Release") { "release" } else { "debug" }
Write-Host "Output directory: $(Join-Path $sdkRoot "target\$targetDir")"
if (-not $CertName) {
    Write-Host ""
    Write-Host "Tip: Use -CertName to sign enclave DLLs after build."
}
