param(
    [string]$Destination = (Join-Path $PSScriptRoot "external\mbedtls")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repository = "https://github.com/Mbed-TLS/mbedtls.git"
$commit = "22098d41c6620ce07cf8a0134d37302355e1e5ef"

if (Test-Path (Join-Path $Destination ".git")) {
    $currentCommit = git -C $Destination rev-parse HEAD
    if ($currentCommit -eq $commit) {
        return
    }

    throw "Existing mbedTLS checkout at $Destination is $currentCommit, expected $commit. Remove it and rerun this script."
}

if (Test-Path $Destination) {
    throw "Destination exists but is not a git checkout: $Destination"
}

$parent = Split-Path -Parent $Destination
New-Item -ItemType Directory -Force -Path $parent | Out-Null

git clone --filter=blob:none --no-checkout $repository $Destination
git -C $Destination checkout $commit
