Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

& (Join-Path $PSScriptRoot "Fetch-MbedTls.ps1")

function Sync-Checkout {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Repository,

        [Parameter(Mandatory = $true)]
        [string]$Commit,

        [Parameter(Mandatory = $true)]
        [string]$Destination
    )

    $Destination = [System.IO.Path]::GetFullPath($Destination)
    if (Test-Path (Join-Path $Destination ".git")) {
        $currentCommit = git -C $Destination rev-parse HEAD
        $expectedCommit = git -C $Destination rev-parse "$Commit^{commit}" 2>$null
        if ($LASTEXITCODE -ne 0) {
            $expectedCommit = $Commit
        }
        if ($currentCommit -eq $expectedCommit) {
            Write-Host "Using existing checkout at $Destination"
            return
        }

        throw "Existing checkout at $Destination is $currentCommit, expected $expectedCommit. Remove it and rerun this script."
    }

    if (Test-Path $Destination) {
        throw "Destination exists but is not a git checkout: $Destination"
    }

    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Destination) | Out-Null
    Write-Host "Fetching $Repository $Commit into $Destination"
    git clone --filter=blob:none --no-checkout $Repository $Destination
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
    git -C $Destination checkout $Commit
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}

Sync-Checkout `
    -Repository "https://github.com/microsoft/wil.git" `
    -Commit "f0c6a81c0c9a4b23b6801f40554b8bec425a83b4" `
    -Destination (Join-Path $PSScriptRoot "external\wil")

Sync-Checkout `
    -Repository "https://github.com/google/flatbuffers.git" `
    -Commit "v24.3.25" `
    -Destination (Join-Path $PSScriptRoot "external\flatbuffers")
