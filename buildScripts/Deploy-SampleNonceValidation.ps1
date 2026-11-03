<#
.SYNOPSIS
Copies signed sample binaries and the validation script to a Hyper-V VM.
.EXAMPLE
.\Deploy-SampleNonceValidation.ps1 -VMName MyVM -Credential (Get-Credential) `
    -CppOutputDirectory C:\repo\SampleApps\SampleApps\_build\x64\Release `
    -RustOutputDirectory C:\repo\rust\sdk\crates\samples\userboundkey\target\debug `
    -RuntimeDirectory 'C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Redist\MSVC\14.44.35112\x64\Microsoft.VC143.CRT'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$VMName,
    [Parameter(Mandatory = $true)]
    [pscredential]$Credential,
    [Parameter(Mandatory = $true)]
    [string]$CppOutputDirectory,
    [Parameter(Mandatory = $true)]
    [string]$RustOutputDirectory,
    [Parameter(Mandatory = $true)]
    [string]$RuntimeDirectory,
    [string]$Destination = ('C:\VbsEnclaveNonceValidation-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repoRoot = Split-Path $PSScriptRoot -Parent
$sourceCommit = & git -C $repoRoot rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Cannot identify the source commit.' }
if ($Destination -notmatch '^[A-Za-z]:\\') { throw 'Destination must be an absolute Windows directory.' }
$destinationPath = [IO.Path]::GetFullPath($Destination)
if ($destinationPath -notmatch '^[A-Za-z]:\\.+') { throw 'Destination must be an absolute Windows directory, not a drive root.' }
$stage = New-Item -ItemType Directory -Path (Join-Path $env:TEMP ('SampleNonceBundle-' + [guid]::NewGuid().ToString('N')))
$session = $null
try {
    $cpp = New-Item -ItemType Directory -Path (Join-Path $stage.FullName 'bin\cpp')
    $rust = New-Item -ItemType Directory -Path (Join-Path $stage.FullName 'bin\rust')
    foreach ($file in @('HostApp.exe', 'HostAppEncryptDecryptThreadpool.exe', 'HostAppUserBound.exe', 'SampleEnclave.dll', 'veil_host.dll')) {
        Copy-Item -LiteralPath (Join-Path $CppOutputDirectory $file) -Destination $cpp.FullName
    }
    foreach ($file in @('userboundkey-sample.exe', 'userboundkey_sample_enclave.dll')) {
        Copy-Item -LiteralPath (Join-Path $RustOutputDirectory $file) -Destination $rust.FullName
    }
    foreach ($file in @('vcruntime140.dll', 'vcruntime140_1.dll', 'msvcp140.dll', 'msvcp140_1.dll', 'msvcp140_2.dll', 'msvcp140_atomic_wait.dll')) {
        $path = Join-Path $RuntimeDirectory $file
        if ((Get-AuthenticodeSignature -LiteralPath $path).Status -ne 'Valid') {
            throw "Runtime DLL does not have a valid signature: $path"
        }
        Copy-Item -LiteralPath $path -Destination $cpp.FullName
        Copy-Item -LiteralPath $path -Destination $rust.FullName
    }
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Invoke-SampleNonceValidation.ps1') -Destination $stage.FullName
    $files = @(Get-ChildItem -LiteralPath $stage.FullName -File -Recurse | ForEach-Object {
        [pscustomobject]@{
            Path = $_.FullName.Substring($stage.FullName.Length + 1)
            SHA256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
        }
    })
    [pscustomobject]@{ SourceCommit = $sourceCommit; Files = $files } |
        ConvertTo-Json -Depth 4 | Out-File -LiteralPath (Join-Path $stage.FullName 'bundle-manifest.json') -Encoding utf8
    $session = New-PSSession -VMName $VMName -Credential $Credential
    Invoke-Command -Session $session -ArgumentList $destinationPath -ScriptBlock {
        param($Path)
        $ErrorActionPreference = 'Stop'
        if (Test-Path -LiteralPath $Path) { throw "Deployment directory already exists: $Path" }
        [void](New-Item -ItemType Directory -Path $Path)
    }
    Copy-Item -Path (Join-Path $stage.FullName '*') -Destination $destinationPath -ToSession $session -Recurse
    Invoke-Command -Session $session -ArgumentList $destinationPath -ScriptBlock {
        param($Path)
        $ErrorActionPreference = 'Stop'
        $manifest = Get-Content -LiteralPath (Join-Path $Path 'bundle-manifest.json') -Raw | ConvertFrom-Json
        foreach ($file in $manifest.Files) {
            if ((Get-FileHash -LiteralPath (Join-Path $Path $file.Path) -Algorithm SHA256).Hash -ne $file.SHA256) {
                throw "Deployment hash mismatch: $($file.Path)"
            }
        }
        [pscustomobject]@{ Directory = $Path; SourceCommit = $manifest.SourceCommit; VerifiedFiles = $manifest.Files.Count }
    }
    Write-Host "In the VM's basic session, run: & '$destinationPath\Invoke-SampleNonceValidation.ps1'"
}
finally {
    if ($null -ne $session) { Remove-PSSession -Session $session }
    Remove-Item -LiteralPath $stage.FullName -Recurse -Force
}
