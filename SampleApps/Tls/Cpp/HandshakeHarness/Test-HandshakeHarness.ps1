param(
    [int]$Port = 9777,
    [uint32]$InputValue = 38
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..\..")).Path
$certDir = Join-Path $repoRoot "SampleApps\Tls\TestServer\test-certs"
$serverScript = Join-Path $repoRoot "SampleApps\Tls\TestServer\Start-TestServer.ps1"
$generateCertsScript = Join-Path $repoRoot "SampleApps\Tls\TestServer\generate-test-certs.ps1"
$harnessBuildScript = Join-Path $PSScriptRoot "Build-HandshakeHarness.ps1"
$harnessExe = Join-Path $PSScriptRoot "bin\x64\Debug\HandshakeHarness.exe"

Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue |
    ForEach-Object { Stop-Process -Id $_.OwningProcess }

Remove-Item -Recurse -Force $certDir -ErrorAction SilentlyContinue
& $generateCertsScript
& $harnessBuildScript -Configuration Debug -Platform x64

$serverOut = Join-Path $env:TEMP "tls-handshake-server-$Port.out"
$serverErr = Join-Path $env:TEMP "tls-handshake-server-$Port.err"
Remove-Item $serverOut, $serverErr -ErrorAction SilentlyContinue

$server = Start-Process `
    -FilePath "pwsh" `
    -ArgumentList @(
        "-NoProfile",
        "-File", $serverScript,
        "-RunInCurrentProcess",
        "-Address", "127.0.0.1",
        "-Port", $Port,
        "-CertificatePath", (Join-Path $certDir "server.pfx"),
        "-MaxConnections", "1") `
    -PassThru `
    -RedirectStandardOutput $serverOut `
    -RedirectStandardError $serverErr

try {
    Start-Sleep -Seconds 2
    $harnessOutput = & $harnessExe `
        --cert (Join-Path $certDir "server-cert.pem") `
        --server localhost `
        --port $Port `
        --input $InputValue

    $exitCode = $LASTEXITCODE
    Wait-Process -Id $server.Id -Timeout 10

    $serverOutput = Get-Content $serverOut -ErrorAction SilentlyContinue
    $serverErrors = Get-Content $serverErr -ErrorAction SilentlyContinue

    $serverHash = ($serverOutput | Select-String -Pattern "^server_cert_sha256=(.+)$").Matches.Groups[1].Value
    $pinnedHash = ($harnessOutput | Select-String -Pattern "^pinned_cert_sha256=(.+)$").Matches.Groups[1].Value

    "--- server stdout ---"
    $serverOutput
    "--- server stderr ---"
    $serverErrors
    "--- harness stdout ---"
    $harnessOutput

    if ($serverHash -ne $pinnedHash) {
        throw "certificate hash mismatch: server=$serverHash harness=$pinnedHash"
    }

    if ($exitCode -ne 0) {
        throw "HandshakeHarness exited with $exitCode"
    }
} finally {
    if (-not $server.HasExited) {
        Stop-Process -Id $server.Id
    }
}
