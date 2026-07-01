param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug",

    [ValidateSet("x64", "ARM64")]
    [string]$Platform = "x64",

    [string]$MbedTlsRoot = (Join-Path $PSScriptRoot "..\..\external\mbedtls")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

& (Join-Path $PSScriptRoot "..\..\Fetch-MbedTls.ps1") -Destination $MbedTlsRoot

$programFilesX86 = ${env:ProgramFiles(x86)}
$vswhere = Join-Path $programFilesX86 "Microsoft Visual Studio\Installer\vswhere.exe"
$msbuild = $null
if (Test-Path $vswhere) {
    $msbuild = & $vswhere `
        -latest `
        -products * `
        -requires Microsoft.Component.MSBuild `
        -find "MSBuild\**\Bin\MSBuild.exe" |
        Select-Object -First 1
}

if (-not $msbuild) {
    $fallback = "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
    if (Test-Path $fallback) {
        $msbuild = $fallback
    }
}

if (-not $msbuild) {
    throw "MSBuild was not found."
}

& $msbuild `
    (Join-Path $PSScriptRoot "HandshakeHarness.vcxproj") `
    /m `
    /restore `
    /p:Configuration=$Configuration `
    /p:Platform=$Platform `
    /p:MbedTlsRoot=$MbedTlsRoot

if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
