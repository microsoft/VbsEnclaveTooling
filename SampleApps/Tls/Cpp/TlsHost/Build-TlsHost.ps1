param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug",

    [ValidateSet("x64", "ARM64")]
    [string]$Platform = "x64"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

& (Join-Path $PSScriptRoot "..\..\Fetch-CppDeps.ps1")

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
    (Join-Path $PSScriptRoot "TlsHost.vcxproj") `
    /m `
    /restore `
    /p:Configuration=$Configuration `
    /p:Platform=$Platform

if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
