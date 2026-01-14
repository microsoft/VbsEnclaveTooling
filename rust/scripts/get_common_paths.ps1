# Locate shared scripts folder
$repoRoot = Resolve-Path "$PSScriptRoot\..\.."
$repoRustRoot = Join-Path $repoRoot "rust"
$scriptsDir = Join-Path $repoRustRoot "scripts"
$SdkWorkspacePath = Join-Path $repoRustRoot "sdk"
$edlCodeGenWorkspacePath = Join-Path $repoRustRoot "edlcodegen"