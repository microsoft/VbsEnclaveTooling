Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$cargoPath = $null
$cargo = Get-Command cargo -ErrorAction SilentlyContinue
if ($cargo) {
    $cargoPath = $cargo.Source
}
if (-not $cargo) {
    $candidate = Join-Path $env:USERPROFILE ".cargo\bin\cargo.exe"
    if (Test-Path $candidate) {
        $cargoPath = $candidate
    }
}

if (-not $cargoPath) {
    throw "cargo was not found. Install Rust with rustup before building this harness."
}

& $cargoPath build --manifest-path (Join-Path $PSScriptRoot "Cargo.toml")
