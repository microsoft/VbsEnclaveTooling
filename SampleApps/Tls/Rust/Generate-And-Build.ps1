# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# Generates the host and enclave Rust binding crates from the shared
# TlsTransport.edl, builds both crates, and (optionally) VEIID-provisions and
# signs the enclave DLL. Mirrors the C++ TLS sample and the Rust helloworld
# sample's generate_and_build_crates.ps1.

param(
    [ValidateSet("debug", "release")]
    [string]$Configuration = "debug",

    [string]$CertName = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRustRoot = Resolve-Path "$PSScriptRoot\..\..\..\rust"
$scriptsDir = Join-Path $repoRustRoot "scripts"

# Import helper that sets $edlCodeGenToolsPath.
. "$scriptsDir\get_codegen_executable.ps1"

$edlPath = Resolve-Path "$PSScriptRoot\..\TlsTransport.edl"
$flatc = Resolve-Path "$repoRustRoot\edlcodegen\crates\libs\edlcodegen-tools\exes\flatbuffers\flatc.exe"
$enclaveCrate = Join-Path $PSScriptRoot "TlsEnclave"
$hostCrate = Join-Path $PSScriptRoot "TlsHost"

function Invoke-Codegen {
    param([string]$TrustLayer, [string]$OutDir, [string[]]$Extra)
    $args = @(
        "--Language", "rust",
        "--Namespace", "tls_sample",
        "--EdlPath", $edlPath,
        "--VirtualTrustLayer", $TrustLayer,
        "--OutputDirectory", $OutDir,
        "--FlatbuffersCompilerPath", $flatc
    ) + $Extra
    & $edlCodeGenToolsPath @args
    if ($LASTEXITCODE -ne 0) {
        throw "edlcodegen failed for $TrustLayer"
    }
}

# Work around an upstream Rust-codegen bug: the generated trusted stub names its
# internal ABI-return local `result`, which shadows an EDL out-parameter also
# named `result` (TlsSample_RunScenario). Rename the internal local so it cannot
# collide. Generated code is not checked in, so this fix-up runs on every
# generation. (Track the upstream fix separately in the code generator.)
function Repair-GeneratedStub {
    param([string]$GenDir)
    Get-ChildItem -Path $GenDir -Recurse -Filter "trusted.rs" | ForEach-Object {
        $text = Get-Content -Raw $_.FullName
        $text = $text -replace 'let result = call_vtl1_export_from_vtl0', 'let __abi_ret = call_vtl1_export_from_vtl0'
        $text = $text -replace '= result\.m_', '= __abi_ret.m_'
        $text = $text -replace 'Ok\(result\.m_', 'Ok(__abi_ret.m_'
        Set-Content -Path $_.FullName -Value $text -NoNewline
    }
}

Write-Host "Generating enclave and host binding crates from TlsTransport.edl..."
Invoke-Codegen -TrustLayer "enclave" -OutDir (Join-Path $enclaveCrate "generated") -Extra @()
Invoke-Codegen -TrustLayer "hostapp" -OutDir (Join-Path $hostCrate "generated") -Extra @("--Vtl0ClassName", "TlsSampleHost")
Repair-GeneratedStub -GenDir (Join-Path $hostCrate "generated")

# The enclave links the shared SDK enclave crate, which needs its own generated
# bindings; generate them once if missing.
$sdkGen = Join-Path $repoRustRoot "sdk\crates\libs\sdk-enclave\generated\vbsenclave_sdk_gen\Cargo.toml"
if (-not (Test-Path $sdkGen)) {
    Write-Host "Generating SDK workspace bindings..."
    & "$repoRustRoot\sdk\generate_codegen_for_workspace.ps1"
}

# Pin the current test server certificate into the enclave image.
& "$enclaveCrate\Generate-ScenarioPolicy.ps1"

# Build both crates individually (they use different panic configurations).
& "$scriptsDir\invoke_cargo_build.ps1" -Path $enclaveCrate -Configuration $Configuration
& "$scriptsDir\invoke_cargo_build.ps1" -Path $hostCrate -Configuration $Configuration

# Provision + sign the enclave DLL when a certificate name is supplied.
$dllPath = Join-Path $enclaveCrate "target\$Configuration\tls_sample_enclave.dll"
& "$scriptsDir\sign-enclave.ps1" -DllPath $dllPath -CertName $CertName

Write-Host "`nBuilt:"
Write-Host "  enclave: $dllPath"
Write-Host "  host:    $(Join-Path $hostCrate "target\$Configuration\tls-sample-host.exe")"
