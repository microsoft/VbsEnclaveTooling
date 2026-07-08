param(
    [string]$Destination = (Join-Path $PSScriptRoot "external\mbedtls")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# git marks pack files read-only, which defeats Remove-Item -Force; clear the
# attribute first so a partial checkout can be cleaned up for a re-run.
function Remove-CheckoutDirectory {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return }
    Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue |
        ForEach-Object { $_.Attributes = 'Normal' }
    Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
}

$Destination = [System.IO.Path]::GetFullPath($Destination)

$repository = "https://github.com/Mbed-TLS/mbedtls.git"
$commit = "22098d41c6620ce07cf8a0134d37302355e1e5ef"

if (Test-Path (Join-Path $Destination ".git")) {
    $currentCommit = git -C $Destination rev-parse HEAD
    if ($currentCommit -eq $commit) {
        Write-Host "Using existing mbedTLS checkout at $Destination"
        return
    }

    throw "Existing mbedTLS checkout at $Destination is $currentCommit, expected $commit. Remove it and rerun this script."
}

if (Test-Path $Destination) {
    throw "Destination exists but is not a git checkout: $Destination"
}

$parent = Split-Path -Parent $Destination
New-Item -ItemType Directory -Force -Path $parent | Out-Null

Write-Host "Fetching mbedTLS $commit into $Destination"
git clone --filter=blob:none --no-checkout $repository $Destination
if ($LASTEXITCODE -ne 0) {
    Remove-CheckoutDirectory $Destination
    throw "git clone of mbedTLS failed (exit $LASTEXITCODE); removed partial checkout."
}

git -C $Destination checkout $commit
if ($LASTEXITCODE -ne 0) {
    Remove-CheckoutDirectory $Destination
    throw "git checkout of mbedTLS $commit failed (exit $LASTEXITCODE); removed partial checkout."
}
