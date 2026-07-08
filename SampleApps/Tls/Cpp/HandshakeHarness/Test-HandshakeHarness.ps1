#requires -Version 7.0
param(
    [int]$Port = 9781,
    [uint32]$InputValue = 38,
    [ValidateSet("x64", "ARM64")]
    [string]$Platform = $(if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "ARM64" } else { "x64" })
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..\..")).Path
$certDir = Join-Path $repoRoot "SampleApps\Tls\TestServer\test-certs"
$serverScript = Join-Path $repoRoot "SampleApps\Tls\TestServer\Start-TestServer.ps1"
$generateCertsScript = Join-Path $repoRoot "SampleApps\Tls\TestServer\generate-test-certs.ps1"
$harnessBuildScript = Join-Path $PSScriptRoot "Build-HandshakeHarness.ps1"
$harnessExe = Join-Path $PSScriptRoot "bin\$Platform\Debug\HandshakeHarness.exe"

if (-not (Test-Path (Join-Path $certDir "server-cert.pem"))) {
    & $generateCertsScript
}
& $harnessBuildScript -Configuration Debug -Platform $Platform

$serverOut = Join-Path $env:TEMP "tls-handshake-server-$Port.out"
$serverErr = Join-Path $env:TEMP "tls-handshake-server-$Port.err"
Remove-Item $serverOut, $serverErr -ErrorAction SilentlyContinue

$server = Start-Process `
    -FilePath (Get-Process -Id $PID).Path `
    -ArgumentList @(
        "-NoProfile",
        "-File", $serverScript,
        "-RunInCurrentProcess",
        "-Address", "127.0.0.1",
        "-Port", $Port,
        "-CertificatePath", (Join-Path $certDir "server.pfx"),
        "-MaxConnections", "2",
        "-StopExisting") `
    -PassThru `
    -RedirectStandardOutput $serverOut `
    -RedirectStandardError $serverErr

function Assert-HarnessResult {
    param([string[]]$Output, [int]$ExitCode, [string]$Label, [bool]$ExpectReject)

    "--- $Label harness output ---"
    $Output
    $status = ($Output | Select-String -Pattern "^status=(\d+)$").Matches.Groups[1].Value
    if ($ExpectReject) {
        # 3 == ValidationFailed: the mismatched pin must be rejected.
        if ($ExitCode -ne 0 -or $status -ne "3") {
            throw "$Label FAILED: expected rejection (status=3), got status=$status exit=$ExitCode"
        }
    } else {
        $decision = ($Output | Select-String -Pattern "^decision=(\w+)$").Matches.Groups[1].Value
        $outputValue = ($Output | Select-String -Pattern "^output_value=(\d+)$").Matches.Groups[1].Value
        if ($ExitCode -ne 0 -or $status -ne "0" -or $decision -ne "Allow" -or [uint32]$outputValue -ne ($InputValue * 37)) {
            throw "$Label FAILED: status=$status decision=$decision output=$outputValue exit=$ExitCode"
        }
    }
    Write-Host "$Label PASSED"
}

try {
    # Wait for the server's readiness banner instead of a fixed sleep.
    $deadline = (Get-Date).AddSeconds(15)
    while ((Get-Date) -lt $deadline) {
        if ((Test-Path $serverOut) -and (Select-String -Path $serverOut -Pattern "listening on" -Quiet)) {
            break
        }
        if ($server.HasExited) {
            throw "server exited early:`n$(Get-Content $serverErr -ErrorAction SilentlyContinue)"
        }
        Start-Sleep -Milliseconds 200
    }

    # Positive: the pinned server certificate is accepted and produces the result.
    $positive = & $harnessExe --cert (Join-Path $certDir "server-cert.pem") --server localhost --port $Port --input $InputValue
    Assert-HarnessResult -Output $positive -ExitCode $LASTEXITCODE -Label "positive" -ExpectReject $false

    # Negative: a mismatched pin (the client certificate) must be rejected.
    $negative = & $harnessExe --cert (Join-Path $certDir "client-cert.pem") --server localhost --port $Port --input $InputValue --expect-reject 1
    Assert-HarnessResult -Output $negative -ExitCode $LASTEXITCODE -Label "negative" -ExpectReject $true

    Write-Host "`nAll HandshakeHarness tests passed."
} finally {
    if (-not $server.HasExited) {
        Stop-Process -Id $server.Id -ErrorAction SilentlyContinue
    }
    Remove-Item $serverOut, $serverErr -ErrorAction SilentlyContinue
}
