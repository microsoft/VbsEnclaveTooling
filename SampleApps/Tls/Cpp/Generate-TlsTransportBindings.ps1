Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
$output = Join-Path $PSScriptRoot "Generated"
$edl = Join-Path $repoRoot "SampleApps\Tls\TlsTransport.edl"
$edlCodegen = Join-Path $repoRoot "rust\edlcodegen\crates\libs\edlcodegen-tools\exes\edlcodegen\edlcodegen.exe"
$flatc = Join-Path $repoRoot "rust\edlcodegen\crates\libs\edlcodegen-tools\exes\flatbuffers\flatc.exe"

Remove-Item -Recurse -Force $output -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $output | Out-Null

& $edlCodegen `
    --Language "C++" `
    --EdlPath $edl `
    --OutputDirectory (Join-Path $output "Enclave") `
    --VirtualTrustLayer "Enclave" `
    --Vtl0ClassName "TlsSampleHost" `
    --Namespace "TlsSample" `
    --FlatbuffersCompilerPath $flatc

& $edlCodegen `
    --Language "C++" `
    --EdlPath $edl `
    --OutputDirectory (Join-Path $output "Host") `
    --VirtualTrustLayer "HostApp" `
    --Vtl0ClassName "TlsSampleHost" `
    --Namespace "TlsSample" `
    --FlatbuffersCompilerPath $flatc
