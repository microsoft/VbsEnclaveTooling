param(
    [int]$Port = 9790
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..\..")).Path
$certDir = Join-Path $repoRoot "SampleApps\Tls\TestServer\test-certs"
$serverScript = Join-Path $repoRoot "SampleApps\Tls\TestServer\Start-TestServer.ps1"
$generateCertsScript = Join-Path $repoRoot "SampleApps\Tls\TestServer\generate-test-certs.ps1"
$buildScript = Join-Path $PSScriptRoot "Build-RustlsHostHarness.ps1"
$harnessExe = Join-Path $PSScriptRoot "target\debug\rustls-host-harness.exe"

Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue |
    ForEach-Object { Stop-Process -Id $_.OwningProcess }

Remove-Item -Recurse -Force $certDir -ErrorAction SilentlyContinue
& $generateCertsScript
& $buildScript

$serverOut = Join-Path $env:TEMP "rustls-host-harness-server-$Port.out"
$serverErr = Join-Path $env:TEMP "rustls-host-harness-server-$Port.err"
Remove-Item $serverOut, $serverErr -ErrorAction SilentlyContinue

$server = Start-Process `
    -FilePath "pwsh" `
    -ArgumentList @(
        "-NoProfile",
        "-File", $serverScript,
        "-RunInCurrentProcess",
        "-Address", "127.0.0.1",
        "-Port", $Port,
        "-CertificatePath", (Join-Path $certDir "server-cert.pem"),
        "-CertificateKeyPath", (Join-Path $certDir "server-key.pem"),
        "-MaxConnections", "1") `
    -PassThru `
    -RedirectStandardOutput $serverOut `
    -RedirectStandardError $serverErr

try {
    Start-Sleep -Seconds 2
    $harnessOutput = & $harnessExe (Join-Path $certDir "server-cert.pem") $Port 38
    $exitCode = $LASTEXITCODE
    Wait-Process -Id $server.Id -Timeout 10

    "--- server stdout ---"
    Get-Content $serverOut -ErrorAction SilentlyContinue
    "--- server stderr ---"
    Get-Content $serverErr -ErrorAction SilentlyContinue
    "--- harness stdout ---"
    $harnessOutput

    if ($exitCode -ne 0) {
        throw "rustls-host-harness exited with $exitCode"
    }
} finally {
    if (-not $server.HasExited) {
        Stop-Process -Id $server.Id
    }
}
