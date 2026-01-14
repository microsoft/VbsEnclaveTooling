# Helper script that invokes cargo to build a Rust crate in debug or release mode.

param(
    [Parameter(Mandatory = $true)]
    [string]$Path,

    [ValidateSet("debug", "release")]
    [string]$Configuration = "debug"
)

$ErrorActionPreference = "Stop"

# Validate cargo
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    throw "cargo not found in PATH. Install Rust or fix PATH."
}

# Validate crate path
if (-not (Test-Path $Path)) {
    throw "Crate path does not exist: $Path"
}

Write-Host "`nBuilding crate at $Path ($Configuration)..."

Push-Location $Path
try {
    if ($Configuration -eq "release") {
        cargo build --release
    } else {
        cargo build
    }
}
finally {
    Pop-Location
}

if ($LASTEXITCODE -ne 0) {
    throw "cargo build failed for crate at: $Path with error code $LASTEXITCODE"
}

Write-Host "Build succeeded."

