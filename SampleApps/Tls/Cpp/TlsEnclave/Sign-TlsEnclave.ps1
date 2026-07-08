param(
    [string]$Configuration = "Debug",
    [string]$Platform = "x64",
    [string]$CertName = "TlsSampleEnclaveCert",
    [string]$CertThumbprint = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$dll = Join-Path $PSScriptRoot "bin\$Platform\$Configuration\TlsEnclave.dll"
if (-not (Test-Path $dll)) {
    throw "TlsEnclave.dll was not found at $dll. Build the enclave first."
}

# Discover the Windows SDK signing tools for this platform rather than hard-coding
# a single SDK version, so the sample builds across machines/architectures.
$arch = if ($Platform -ieq "ARM64") { "arm64" } else { "x64" }
$sdkBinRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin"
$veiid = Get-ChildItem $sdkBinRoot -Directory -ErrorAction SilentlyContinue |
    Sort-Object Name -Descending |
    ForEach-Object { Join-Path $_.FullName "$arch\veiid.exe" } |
    Where-Object { Test-Path $_ } |
    Select-Object -First 1
$signTool = Get-ChildItem $sdkBinRoot -Directory -ErrorAction SilentlyContinue |
    Sort-Object Name -Descending |
    ForEach-Object { Join-Path $_.FullName "$arch\signtool.exe" } |
    Where-Object { Test-Path $_ } |
    Select-Object -First 1

if (-not $veiid) {
    throw "veiid.exe was not found under $sdkBinRoot for $arch."
}
if (-not $signTool) {
    throw "signtool.exe was not found under $sdkBinRoot for $arch."
}

& $veiid $dll
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

$signArgs = @("sign", "/ph", "/fd", "SHA256")
if ($CertThumbprint) {
    $signArgs += @("/sha1", $CertThumbprint, "/s", "My")
} else {
    $signArgs += @("/n", $CertName)
}
$signArgs += $dll

& $signTool @signArgs
if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 2) {
    exit $LASTEXITCODE
}
