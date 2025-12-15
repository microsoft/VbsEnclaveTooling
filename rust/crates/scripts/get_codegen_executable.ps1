# Helper script that ensures the EDL code generation tool is built and returns its path.
$repoRoot = (Get-Item $PSScriptRoot).Parent.Parent.Parent.FullName
$repoBuildScript = Join-Path $repoRoot "buildScripts\build.ps1"
$edlCodeGenToolsPath = Join-Path $repoRoot "_build\x64\release\edlcodegen.exe"

$ErrorActionPreference = "Stop"

if (-not (Test-Path $edlCodeGenToolsPath)) {
    Write-Host "edlcodegen.exe not found at $edlCodeGenToolsPath. Building edlcodegen.exe..."
    & $repoBuildScript -Platforms "x64" -Configurations "Release" -NugetPackagesToOutput "None"
}
