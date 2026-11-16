<#
.SYNOPSIS
Runs focused encryption sample checks, with each authentication step identified.
.DESCRIPTION
Run in a basic VM console session with VBS enabled. The script supplies menu
input and checks actual sample output; you only respond to Windows Hello.
The default runs Basic nonce/round-trip checks with nonempty input and no Hello.
Select one user-bound sample explicitly. Use TestGroup Tampering for rejection
tests, or All for both groups. IncludeEmptyInput adds a second set of cases.
Basic and Threadpool do not use Windows Hello. The user-bound samples require
Windows Hello enrollment for the account running this script inside the VM.
Use a disposable test account: creating a user-bound key replaces the sample's
Windows Hello credential named MyEncryptionKey-001.
.EXAMPLE
.\Invoke-SampleNonceValidation.ps1 -Sample CppUserBound -TestGroup Nonce
.EXAMPLE
.\Invoke-SampleNonceValidation.ps1 -Sample RustUserBound -TestGroup Tampering
.EXAMPLE
.\Invoke-SampleNonceValidation.ps1 -Sample All -TestGroup All -IncludeEmptyInput
.EXAMPLE
.\Invoke-SampleNonceValidation.ps1 -Sample RustUserBound -PreflightOnly
#>
[CmdletBinding()]
param(
    [ValidateSet('All', 'Basic', 'Threadpool', 'CppUserBound', 'RustUserBound')]
    [string]$Sample = 'Basic',
    [ValidateSet('Nonce', 'Tampering', 'All')]
    [string]$TestGroup = 'Nonce',
    [switch]$IncludeEmptyInput,
    [string]$BundleRoot = $PSScriptRoot,
    [ValidateRange(30, 600)]
    [int]$TimeoutSeconds = 180,
    [switch]$PreflightOnly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Read-SampleFile {
    param([string]$Path, [bool]$LengthPrefixed)
    $bytes = [IO.File]::ReadAllBytes($Path)
    $dataOffset = 0
    if ($LengthPrefixed) {
        # SaveBinaryData writes a size_t before the payload in the x64 C++ samples.
        if ($bytes.Length -lt 8 -or [BitConverter]::ToUInt64($bytes, 0) -ne $bytes.Length - 8) {
            throw "Invalid binary payload length in $Path"
        }
        $dataOffset = 8
    }
    [pscustomobject]@{
        Bytes = $bytes
        DataOffset = $dataOffset
        DataLength = $bytes.Length - $dataOffset
    }
}

function Read-CipherLayout {
    param([string]$Path, [bool]$Combined, [int]$PlaintextBytes, [bool]$LengthPrefixed)
    $file = Read-SampleFile $Path $LengthPrefixed
    $bytes = $file.Bytes
    $nonceOffset = $file.DataOffset
    if ($Combined) {
        if ($file.DataLength -lt 32 -or [BitConverter]::ToUInt32($bytes, $file.DataOffset) -ne 16) {
            throw "Invalid tag/nonce header in $Path"
        }
        $nonceOffset += 20
    }
    $headerLength = $nonceOffset + 12
    if ($bytes.Length -ne $headerLength + $PlaintextBytes) {
        throw "Unexpected ciphertext length in $Path (expected $($headerLength + $PlaintextBytes) bytes; got $($bytes.Length))."
    }
    [pscustomobject]@{
        Bytes = $bytes
        Nonce = [BitConverter]::ToString($bytes, $nonceOffset, 12)
        NonceOffset = $nonceOffset
        CipherOffset = $headerLength
        DataOffset = $file.DataOffset
    }
}

function Invoke-SampleProcess {
    param([string]$Executable, [string[]]$Commands, [string]$Directory, [string]$LogPath,
        [scriptblock]$Interaction, [string]$Step, [string]$HelloAction)
    Write-Host "`n$Step"
    if ($HelloAction) {
        Write-Host "WINDOWS HELLO: $HelloAction"
        Write-Host 'This starts a fresh enclave; approval from a previous test does not carry over.'
    }
    Write-Host "Sample log: $LogPath"
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
    $interactiveOutput = New-Object Text.StringBuilder
    try {
        [void]$process.Start()
        $started = $true
        $stderr = $process.StandardError.ReadToEndAsync()
        if ($null -ne $Interaction) {
            & $Interaction $process $interactiveOutput
        }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $process.StandardInput.WriteLine(($Commands -join "`r`n"))
        $process.StandardInput.Close()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $process.Kill()
            $process.WaitForExit()
            $output = $interactiveOutput.ToString() + $stdout.GetAwaiter().GetResult() +
                $stderr.GetAwaiter().GetResult()
            $output | Out-File -LiteralPath $LogPath -Encoding utf8
            throw "Sample timed out. See $LogPath; check Windows Hello and basic session mode."
        }
        $output = $interactiveOutput.ToString() + $stdout.GetAwaiter().GetResult() +
            $stderr.GetAwaiter().GetResult()
        $output | Out-File -LiteralPath $LogPath -Encoding utf8
        Write-Host $output
        [pscustomobject]@{ ExitCode = $process.ExitCode; Output = $output; LogPath = $LogPath }
    }
    catch {
        if ($started) {
            if (-not $process.HasExited) {
                $process.Kill()
                $process.WaitForExit()
            }
            if ($null -eq $stdout) { $stdout = $process.StandardOutput.ReadToEndAsync() }
            if ($null -ne $stderr) {
                ($interactiveOutput.ToString() + $stdout.GetAwaiter().GetResult() +
                    $stderr.GetAwaiter().GetResult()) |
                    Out-File -LiteralPath $LogPath -Encoding utf8
            }
        }
        throw
    }
    finally {
        $process.Dispose()
    }
}

function Invoke-SampleMenuStep {
    param($Process, [Text.StringBuilder]$Output, [string[]]$Commands)
    if ($Commands.Count -gt 0) {
        $Process.StandardInput.WriteLine(($Commands -join "`r`n"))
        $Process.StandardInput.Flush()
    }
    $stepOutput = New-Object Text.StringBuilder
    $buffer = New-Object char[] 1
    $timer = [Diagnostics.Stopwatch]::StartNew()
    while (-not $stepOutput.ToString().EndsWith('Enter your choice: ')) {
        $read = $Process.StandardOutput.ReadAsync($buffer, 0, 1)
        $remaining = $TimeoutSeconds * 1000 - [int]$timer.ElapsedMilliseconds
        if ($remaining -le 0 -or -not $read.Wait($remaining)) {
            throw 'Sample timed out waiting for its menu; check Windows Hello.'
        }
        if ($read.GetAwaiter().GetResult() -eq 0) {
            throw 'Sample exited before returning to its menu.'
        }
        [void]$stepOutput.Append($buffer[0])
        [void]$Output.Append($buffer[0])
    }
    $stepOutput.ToString()
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
Write-Host 'Bundle hashes and VBS preflight passed. User-bound tests also require Windows Hello enrollment for this VM account; use basic session mode.'
if ($PreflightOnly) {
    return
}

$kinds = @('Basic', 'Threadpool', 'CppUserBound', 'RustUserBound')
if ($Sample -ne 'All') {
    $kinds = @($Sample)
}
$texts = @('VBS nonce validation')
if ($IncludeEmptyInput) { $texts += '' }
Write-Host "Selected samples: $($kinds -join ', '); test group: $TestGroup; input cases: $($texts.Count)."
Write-Host 'Nonce checks exercise valid encryption/decryption; tampering checks intentionally produce sample errors.'
if ($Sample -eq 'All') {
    Write-Host 'All includes BOTH user-bound samples, each with its own Windows Hello approvals.'
}
if ($kinds -contains 'CppUserBound' -or $kinds -contains 'RustUserBound') {
    Write-Warning 'Use a disposable test account. This replaces the sample Windows Hello credential MyEncryptionKey-001; old sample keys/data may stop working.'
    Write-Host 'Each labeled test starts a new process and may need Hello. Initial key creation plus encryption may need two approvals.'
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
        $lengthPrefixed = -not $rust
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
        # Manual sample runs can leave sealed keys beside the binaries.
        foreach ($file in $manifest.Files) {
            $runtimePath = [IO.Path]::GetFullPath((Join-Path $BundleRoot $file.Path))
            if ((Split-Path $runtimePath -Parent) -eq $source -and
                [IO.Path]::GetExtension($runtimePath) -in @('.exe', '.dll')) {
                Copy-Item -LiteralPath $runtimePath -Destination $directory
            }
        }
        $executable = Join-Path $directory $exeName
        $dataFiles = @('encrypted', 'tag')
        if ($combined) { $dataFiles = @('encrypted_userbound') }
        if ($kind -eq 'Threadpool') { $dataFiles = @('encrypted1', 'tag1', 'encrypted2', 'tag2') }
        $keyPath = Join-Path $directory 'MyEncryptionKey-001'
        $sequence = 0

        foreach ($text in $texts) {
            $case = 'encrypt'
            $sequence++
            $helloAction = ''
            $commands = @('1', $text, '3')
            if ($kind -eq 'Threadpool') { $commands = @('1', $text, $text, '3') }
            if ($combined) {
                $keyOption = '1'
                if (Test-Path -LiteralPath $keyPath) { $keyOption = '2' }
                $commands = @($keyOption, '4', $text, '6')
                $helloAction = 'Approve creating the test key and unlocking it for initial encryption.'
                if ($keyOption -eq '2') {
                    $helloAction = 'Approve unlocking the existing test key to encrypt this input.'
                }
            }
            $result = Invoke-SampleProcess $executable $commands $directory `
                (Join-Path $directory "$sequence-encrypt.txt") `
                -Step "[$kind / $TestGroup / step $sequence] Encrypt input (length $($text.Length))." `
                -HelloAction $helloAction
            if ($result.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $keyPath)) {
                throw "Encryption failed for $kind (exit code $($result.ExitCode)). See $($result.LogPath)."
            }
            $plainBytes = [Text.Encoding]::Unicode.GetByteCount($text)
            $layout = Read-CipherLayout (Join-Path $directory $dataFiles[0]) $combined $plainBytes $lengthPrefixed
            if ($kind -eq 'Threadpool') {
                $other = Read-CipherLayout (Join-Path $directory 'encrypted2') $false $plainBytes $lengthPrefixed
                if ($layout.Nonce -eq $other.Nonce) { throw 'Parallel messages reused a nonce.' }
                $results.Add([pscustomobject]@{ Sample = $kind; Case = "parallel nonce uniqueness (length $($text.Length))"; Status = 'PASS' })
            }
            if (-not $combined) {
                foreach ($file in $dataFiles | Where-Object { $_ -like 'tag*' }) {
                    $tagFile = Read-SampleFile (Join-Path $directory $file) $lengthPrefixed
                    if ($tagFile.DataLength -ne 16) {
                        throw "Invalid tag size in $file"
                    }
                }
            }
            if ($combined -and $TestGroup -ne 'Tampering') {
                $case = 'same-key nonce uniqueness'
                $keyHash = (Get-FileHash -LiteralPath $keyPath -Algorithm SHA256).Hash
                $sequence++
                $result = Invoke-SampleProcess $executable @('2', '4', $text, '6') $directory `
                    (Join-Path $directory "$sequence-repeat.txt") `
                    -Step "[$kind / $TestGroup / step $sequence] Verify a fresh nonce after restarting with the same sealed key." `
                    -HelloAction 'Approve unlocking the same test key for another encryption.'
                $other = Read-CipherLayout (Join-Path $directory $dataFiles[0]) $true $plainBytes $lengthPrefixed
                if ($result.ExitCode -ne 0 -or $layout.Nonce -eq $other.Nonce -or
                    $keyHash -ne (Get-FileHash -LiteralPath $keyPath -Algorithm SHA256).Hash) {
                    throw 'Repeated encryption did not use the same sealed key with a fresh nonce.'
                }
                $layout = $other
                $results.Add([pscustomobject]@{ Sample = $kind; Case = "$case (length $($text.Length))"; Status = 'PASS' })

                $case = 'cached-key nonce uniqueness and round trips'
                $sequence++
                $cached = @{}
                $result = Invoke-SampleProcess $executable @('6') $directory `
                    (Join-Path $directory "$sequence-cached-key.txt") `
                    -Step "[$kind / $TestGroup / step $sequence] Encrypt twice and decrypt both using one live cached key." `
                    -HelloAction 'Approve the first encryption to unlock the key; subsequent operations reuse it in this process.' `
                    -Interaction {
                        param($process, $output)
                        [void](Invoke-SampleMenuStep $process $output @())
                        [void](Invoke-SampleMenuStep $process $output @('2'))
                        $path = Join-Path $directory $dataFiles[0]
                        Remove-Item -LiteralPath $path
                        Write-Host "[$kind / cached key] First encryption: approve Windows Hello to unlock the key."
                        [void](Invoke-SampleMenuStep $process $output @('4', $text))
                        $first = Read-CipherLayout $path $true $plainBytes $lengthPrefixed
                        Remove-Item -LiteralPath $path
                        Write-Host "[$kind / cached key] Second encryption: reuse the loaded key."
                        [void](Invoke-SampleMenuStep $process $output @('4', $text))
                        $second = Read-CipherLayout $path $true $plainBytes $lengthPrefixed
                        if ($first.Nonce -eq $second.Nonce) {
                            throw 'Repeated encryption with one live cached key reused a nonce.'
                        }
                        foreach ($cipher in @($second, $first)) {
                            [IO.File]::WriteAllBytes($path, $cipher.Bytes)
                            Write-Host "[$kind / cached key] Verify decryption using the loaded key."
                            $decrypted = Invoke-SampleMenuStep $process $output @('5')
                            Assert-Decryption ([pscustomobject]@{ ExitCode = 0; Output = $decrypted }) $text $kind
                        }
                        [IO.File]::WriteAllBytes($path, $second.Bytes)
                        $cached.Layout = $second
                    }
                if ($result.ExitCode -ne 0 -or
                    $keyHash -ne (Get-FileHash -LiteralPath $keyPath -Algorithm SHA256).Hash) {
                    throw 'Cached-key validation failed or changed the sealed key.'
                }
                $layout = $cached.Layout
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
            $helloAction = ''
            if ($combined) { $helloAction = 'Approve unlocking the test key to verify valid decryption.' }
            $result = Invoke-SampleProcess $executable $decryptCommands $directory `
                (Join-Path $directory "$sequence-roundtrip.txt") `
                -Step "[$kind / $TestGroup / step $sequence] Verify valid decryption after restarting." `
                -HelloAction $helloAction
            Assert-Decryption $result $text $kind
            $results.Add([pscustomobject]@{ Sample = $kind; Case = "$case (length $($text.Length))"; Status = 'PASS' })

            if ($TestGroup -eq 'Nonce') { continue }
            $mutations = @('nonce', 'tag', 'truncated')
            if ($plainBytes -gt 0) { $mutations += 'ciphertext' }
            $failureTargets = @('')
            if ($kind -eq 'Threadpool') { $failureTargets = @('1', '2', '1,2') }
            foreach ($mutation in $mutations) {
                foreach ($target in $failureTargets) {
                    foreach ($file in $snapshot.Keys) {
                        [IO.File]::WriteAllBytes((Join-Path $directory $file), $snapshot[$file])
                    }
                    $case = "$mutation rejection"
                    if ($kind -eq 'Threadpool') { $case += " (workers $target)" }
                    foreach ($worker in $target.Split(',')) {
                        $path = Join-Path $directory $dataFiles[0]
                        if ($kind -eq 'Threadpool') { $path = Join-Path $directory "encrypted$worker" }
                        $workerLayout = Read-CipherLayout $path $combined $plainBytes $lengthPrefixed
                        $bytes = [byte[]]$workerLayout.Bytes.Clone()
                        $offset = $workerLayout.NonceOffset
                        if ($mutation -eq 'tag') {
                            $offset = $workerLayout.DataOffset + 4
                            if (-not $combined) {
                                $path = Join-Path $directory "tag$worker"
                                $tagFile = Read-SampleFile $path $lengthPrefixed
                                $offset = $tagFile.DataOffset
                            }
                            $bytes = [IO.File]::ReadAllBytes($path)
                        }
                        if ($mutation -eq 'ciphertext') { $offset = $workerLayout.CipherOffset }
                        if ($mutation -eq 'truncated') {
                            $bytes = [byte[]]$bytes[0..($workerLayout.CipherOffset - 2)]
                            if ($lengthPrefixed) {
                                [BitConverter]::GetBytes([uint64]($bytes.Length - $workerLayout.DataOffset)).CopyTo($bytes, 0)
                            }
                        }
                        else { $bytes[$offset] = $bytes[$offset] -bxor 1 }
                        [IO.File]::WriteAllBytes($path, $bytes)
                    }
                    $sequence++
                    $helloAction = ''
                    if ($combined) {
                        $helloAction = "Approve unlocking the test key for $mutation rejection. The expected result is a sample error, not plaintext."
                        if ($mutation -eq 'truncated') {
                            $helloAction = ''
                        }
                    }
                    $result = Invoke-SampleProcess $executable $decryptCommands $directory `
                        (Join-Path $directory "$sequence-$mutation-$target.txt") `
                        -Step "[$kind / $TestGroup / step $sequence] EXPECTED FAILURE: $case (input length $($text.Length))." `
                        -HelloAction $helloAction
                    Assert-Rejection $result $kind ($mutation -eq 'truncated')
                    $results.Add([pscustomobject]@{ Sample = $kind; Case = "$case (length $($text.Length))"; Status = 'PASS' })
                }
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
