# Run rust format on the specified Rust workspace
param(
    [Parameter(Mandatory = $true)]
    [string]$WorkspacePath
)

$ErrorActionPreference = "Stop"

Write-Host "Checking rustfmt installation"

if (-not (Get-Command rustfmt -ErrorAction SilentlyContinue)) {
    throw "rustfmt is not installed. Run: rustup component add rustfmt"
}

rustfmt --version

Write-Host "Starting rustfmt on workspace"

Push-Location $WorkspacePath
try {
    cargo fmt --all
}
finally {
    Pop-Location
}

if ($LASTEXITCODE -ne 0) {
    throw "rustfmt failed with exit code $LASTEXITCODE"
}

Write-Host "rustfmt Completed successfully"
