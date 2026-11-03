<#
.SYNOPSIS
Runs the encryption samples interactively, including Windows Hello prompts.
.DESCRIPTION
Run in a basic VM console session with VBS enabled. The script supplies menu
input and checks actual sample output; you only respond to Windows Hello.
Use a disposable test account: creating a user-bound key replaces the sample's
Windows Hello credential named MyEncryptionKey-001.
.EXAMPLE
.\Invoke-SampleNonceValidation.ps1 -Sample All
.EXAMPLE
.\Invoke-SampleNonceValidation.ps1 -Sample RustUserBound -PreflightOnly
#>
[CmdletBinding()]
param(
    [ValidateSet('All', 'Basic', 'Threadpool', 'CppUserBound', 'RustUserBound')]
    [string]$Sample = 'All',
    [string]$BundleRoot = $PSScriptRoot,
    [ValidateRange(30, 600)]
    [int]$TimeoutSeconds = 180,
    [switch]$PreflightOnly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Read-CipherLayout {
    param([string]$Path, [bool]$Combined, [int]$PlaintextBytes)
    $bytes = [IO.File]::ReadAllBytes($Path)
    $nonceOffset = 0
    if ($Combined) {
        if ($bytes.Length -lt 32 -or [BitConverter]::ToUInt32($bytes, 0) -ne 16) {
            throw "Invalid tag/nonce header in $Path"
        }
        $nonceOffset = 20
    }
    $headerLength = $nonceOffset + 12
    if ($bytes.Length -ne $headerLength + $PlaintextBytes) {
        throw "Unexpected ciphertext length in $Path"
    }
    [pscustomobject]@{
        Bytes = $bytes
        Nonce = [BitConverter]::ToString($bytes, $nonceOffset, 12)
        NonceOffset = $nonceOffset
        CipherOffset = $headerLength
    }
}

function Invoke-SampleProcess {
    param([string]$Executable, [string[]]$Commands, [string]$Directory, [string]$LogPath)
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $Executable
    $start.WorkingDirectory = $Directory
    $start.UseShellExecute = $false
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $start
    $started = $false
    $stdout = $null
    $stderr = $null
    try {
        [void]$process.Start()
        $started = $true
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $process.StandardInput.WriteLine(($Commands -join "`r`n"))
        $process.StandardInput.Close()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $process.Kill()
            $process.WaitForExit()
            $output = $stdout.GetAwaiter().GetResult() + $stderr.GetAwaiter().GetResult()
            $output | Out-File -LiteralPath $LogPath -Encoding utf8
            throw "Sample timed out. See $LogPath; check Windows Hello and basic session mode."
        }
        $output = $stdout.GetAwaiter().GetResult() + $stderr.GetAwaiter().GetResult()
        $output | Out-File -LiteralPath $LogPath -Encoding utf8
        Write-Host $output
        [pscustomobject]@{ ExitCode = $process.ExitCode; Output = $output }
    }
    catch {
        if ($started) {
            if (-not $process.HasExited) {
                $process.Kill()
                $process.WaitForExit()
            }
            if ($null -ne $stdout -and $null -ne $stderr) {
                ($stdout.GetAwaiter().GetResult() + $stderr.GetAwaiter().GetResult()) |
                    Out-File -LiteralPath $LogPath -Encoding utf8
            }
        }
        throw
    }
    finally {
        $process.Dispose()
    }
}

function Assert-Decryption {
    param($Result, [string]$Text, [string]$Kind)
    $labels = @('Decrypted string:')
    if ($Kind -eq 'Threadpool') {
        $labels = @('Decrypted first string:', 'Decrypted second string:')
    }
    elseif ($Kind -eq 'RustUserBound') {
        $labels = @('Decrypted data:')
    }
    if ($Result.ExitCode -ne 0) {
        throw "Sample exited with $($Result.ExitCode) during a valid round trip."
    }
    foreach ($label in $labels) {
        $pattern = '(?m)' + [regex]::Escape($label) + '[ \t]*' +
            [regex]::Escape($Text) + '[ \t]*\r?$'
        if ($Result.Output -notmatch $pattern) {
            throw "Expected plaintext was not returned for $label"
        }
    }
}

function Assert-Rejection {
    param($Result, [string]$Kind, [bool]$Malformed)
    # Rust maps tag mismatch to E_INVALIDARG; C++ preserves STATUS_AUTH_TAG_MISMATCH.
    $expected = '(?i)c000a002|-1073700862'
    $failureMarker = 'Enter your choice:'
    if ($Kind -eq 'RustUserBound') { $failureMarker = 'Decryption failed:' }
    if ($Kind -eq 'CppUserBound') { $failureMarker = 'Error: Operation failed' }
    if ($Kind -eq 'RustUserBound' -or $Malformed) {
        $expected = '(?i)80070057|-2147024809'
    }
    if ($Result.Output -match 'Decrypted (data|(?:first |second )?string):' -or
        $Result.Output -notmatch $expected -or $Result.Output -notmatch $failureMarker) {
        throw 'Expected authentication/format rejection was not observed. Inspect the sample log.'
    }
}

$BundleRoot = (Resolve-Path -LiteralPath $BundleRoot).Path
$manifest = Get-Content -LiteralPath (Join-Path $BundleRoot 'bundle-manifest.json') -Raw |
    ConvertFrom-Json
foreach ($file in $manifest.Files) {
    $path = [IO.Path]::GetFullPath((Join-Path $BundleRoot $file.Path))
    if (-not $path.StartsWith($BundleRoot.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Manifest path is outside the bundle: $($file.Path)"
    }
    if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $file.SHA256) {
        throw "Bundle file differs from the deployed build: $($file.Path)"
    }
}
if ([IntPtr]::Size -ne 8) {
    throw 'Run this script from 64-bit PowerShell.'
}
if (-not ('SampleNonceNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
public static class SampleNonceNative {
    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool IsEnclaveTypeSupported(uint type);
}
'@
}
$vbsStatus = (Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard `
    -ClassName Win32_DeviceGuard).VirtualizationBasedSecurityStatus
Write-Host "Source commit: $($manifest.SourceCommit)"
Write-Host "VBS status: $vbsStatus (2 means running)"
if (-not [SampleNonceNative]::IsEnclaveTypeSupported(0x10) -or $vbsStatus -ne 2) {
    throw 'BLOCKED: VBS enclaves are unavailable. Enable Memory integrity in the VM and restart, then rerun. No settings were changed.'
}
Write-Host 'Bundle hashes and VBS preflight passed. Use basic VM session mode for Windows Hello.'
if ($PreflightOnly) {
    return
}

$kinds = @('Basic', 'Threadpool', 'CppUserBound', 'RustUserBound')
if ($Sample -ne 'All') {
    $kinds = @($Sample)
}
if ($kinds -contains 'CppUserBound' -or $kinds -contains 'RustUserBound') {
    Write-Warning 'Use a disposable test account. This replaces the sample Windows Hello credential MyEncryptionKey-001; old sample keys/data may stop working.'
    if ((Read-Host 'Type RUN TESTS to continue') -cne 'RUN TESTS') {
        throw 'Validation cancelled before creating keys.'
    }
}
$runRoot = Join-Path $BundleRoot ('results\' + (Get-Date -Format 'yyyyMMdd-HHmmss') +
    '-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
[void](New-Item -ItemType Directory -Path $runRoot)
$results = New-Object 'Collections.Generic.List[object]'
$kind = ''
$case = 'setup'
try {
    foreach ($kind in $kinds) {
        $combined = $kind -in @('CppUserBound', 'RustUserBound')
        $rust = $kind -eq 'RustUserBound'
        $source = Join-Path $BundleRoot 'bin\cpp'
        $exeName = 'HostApp.exe'
        if ($kind -eq 'Threadpool') { $exeName = 'HostAppEncryptDecryptThreadpool.exe' }
        if ($kind -eq 'CppUserBound') { $exeName = 'HostAppUserBound.exe' }
        if ($rust) {
            $source = Join-Path $BundleRoot 'bin\rust'
            $exeName = 'userboundkey-sample.exe'
        }
        $directory = Join-Path $runRoot $kind
        [void](New-Item -ItemType Directory -Path $directory)
        Copy-Item -Path (Join-Path $source '*') -Destination $directory
        $executable = Join-Path $directory $exeName
        $dataFiles = @('encrypted', 'tag')
        if ($combined) { $dataFiles = @('encrypted_userbound') }
        if ($kind -eq 'Threadpool') { $dataFiles = @('encrypted1', 'tag1', 'encrypted2', 'tag2') }
        $keyPath = Join-Path $directory 'MyEncryptionKey-001'
        $sequence = 0

        foreach ($text in @('VBS nonce validation', '')) {
            $case = 'encrypt'
            $sequence++
            Write-Host "`n[$kind/$case] Text length: $($text.Length). Respond to Windows Hello if prompted."
            $commands = @('1', $text, '3')
            if ($kind -eq 'Threadpool') { $commands = @('1', $text, $text, '3') }
            if ($combined) {
                $keyOption = '1'
                if (Test-Path -LiteralPath $keyPath) { $keyOption = '2' }
                $commands = @($keyOption, '4', $text, '6')
            }
            $result = Invoke-SampleProcess $executable $commands $directory `
                (Join-Path $directory "$sequence-encrypt.txt")
            if ($result.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $keyPath)) {
                throw "Encryption failed for $kind."
            }
            $plainBytes = [Text.Encoding]::Unicode.GetByteCount($text)
            $layout = Read-CipherLayout (Join-Path $directory $dataFiles[0]) $combined $plainBytes
            if ($kind -eq 'Threadpool') {
                $other = Read-CipherLayout (Join-Path $directory 'encrypted2') $false $plainBytes
                if ($layout.Nonce -eq $other.Nonce) { throw 'Parallel messages reused a nonce.' }
                $results.Add([pscustomobject]@{ Sample = $kind; Case = "parallel nonce uniqueness (length $($text.Length))"; Status = 'PASS' })
            }
            if (-not $combined) {
                foreach ($file in $dataFiles | Where-Object { $_ -like 'tag*' }) {
                    if ((Get-Item -LiteralPath (Join-Path $directory $file)).Length -ne 16) {
                        throw "Invalid tag size in $file"
                    }
                }
            }
            if ($combined) {
                $case = 'same-key nonce uniqueness'
                $keyHash = (Get-FileHash -LiteralPath $keyPath -Algorithm SHA256).Hash
                $sequence++
                $result = Invoke-SampleProcess $executable @('2', '4', $text, '6') $directory `
                    (Join-Path $directory "$sequence-repeat.txt")
                $other = Read-CipherLayout (Join-Path $directory $dataFiles[0]) $true $plainBytes
                if ($result.ExitCode -ne 0 -or $layout.Nonce -eq $other.Nonce -or
                    $keyHash -ne (Get-FileHash -LiteralPath $keyPath -Algorithm SHA256).Hash) {
                    throw 'Repeated encryption did not use the same sealed key with a fresh nonce.'
                }
                $layout = $other
                $results.Add([pscustomobject]@{ Sample = $kind; Case = "$case (length $($text.Length))"; Status = 'PASS' })
            }
            $snapshot = @{}
            foreach ($file in @('MyEncryptionKey-001') + $dataFiles) {
                $snapshot[$file] = [IO.File]::ReadAllBytes((Join-Path $directory $file))
            }
            $decryptCommands = @('2', '3')
            if ($combined) { $decryptCommands = @('2', '5', '6') }
            $case = 'round trip'
            $sequence++
            $result = Invoke-SampleProcess $executable $decryptCommands $directory `
                (Join-Path $directory "$sequence-roundtrip.txt")
            Assert-Decryption $result $text $kind
            $results.Add([pscustomobject]@{ Sample = $kind; Case = "$case (length $($text.Length))"; Status = 'PASS' })

            $mutations = @('nonce', 'tag', 'truncated')
            if ($plainBytes -gt 0) { $mutations += 'ciphertext' }
            foreach ($mutation in $mutations) {
                foreach ($file in $snapshot.Keys) {
                    [IO.File]::WriteAllBytes((Join-Path $directory $file), $snapshot[$file])
                }
                $case = "$mutation rejection"
                $path = Join-Path $directory $dataFiles[0]
                $bytes = [byte[]]$layout.Bytes.Clone()
                $offset = $layout.NonceOffset
                if ($mutation -eq 'tag') {
                    $offset = 4
                    if (-not $combined) { $path = Join-Path $directory 'tag'; $offset = 0 }
                    if ($kind -eq 'Threadpool') { $path = Join-Path $directory 'tag1'; $offset = 0 }
                    $bytes = [IO.File]::ReadAllBytes($path)
                }
                if ($mutation -eq 'ciphertext') { $offset = $layout.CipherOffset }
                if ($mutation -eq 'truncated') {
                    $bytes = [byte[]]$bytes[0..($layout.CipherOffset - 2)]
                }
                else { $bytes[$offset] = $bytes[$offset] -bxor 1 }
                [IO.File]::WriteAllBytes($path, $bytes)
                $sequence++
                $result = Invoke-SampleProcess $executable $decryptCommands $directory `
                    (Join-Path $directory "$sequence-$mutation.txt")
                Assert-Rejection $result $kind ($mutation -eq 'truncated')
                $results.Add([pscustomobject]@{ Sample = $kind; Case = "$case (length $($text.Length))"; Status = 'PASS' })
            }
            foreach ($file in $snapshot.Keys) {
                [IO.File]::WriteAllBytes((Join-Path $directory $file), $snapshot[$file])
            }
        }
    }
}
catch {
    $results.Add([pscustomobject]@{ Sample = $kind; Case = "$case : $($_.Exception.Message)"; Status = 'FAIL' })
    throw
}
finally {
    $results | Export-Csv -LiteralPath (Join-Path $runRoot 'results.csv') -NoTypeInformation
    Write-Host "Results and sample logs: $runRoot"
}
$results | Format-Table -AutoSize
Write-Host 'All selected sample validation cases passed.'
