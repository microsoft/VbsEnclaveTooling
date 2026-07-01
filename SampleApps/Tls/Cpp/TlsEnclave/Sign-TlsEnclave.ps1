param(
    [string]$Configuration = "Debug",
    [string]$Platform = "x64",
    [string]$CertName = "TlsSampleEnclaveCert"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$dll = Join-Path $PSScriptRoot "bin\$Platform\$Configuration\TlsEnclave.dll"
if (-not (Test-Path $dll)) {
    throw "TlsEnclave.dll was not found at $dll. Build the enclave first."
}

$sdkBin = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64"
$veiid = Join-Path $sdkBin "veiid.exe"
$signTool = Join-Path $sdkBin "signtool.exe"

if (-not (Test-Path $veiid)) {
    throw "veiid.exe was not found at $veiid."
}
if (-not (Test-Path $signTool)) {
    throw "signtool.exe was not found at $signTool."
}

& $veiid $dll
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

& $signTool sign /ph /fd SHA256 /n $CertName $dll
if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 2) {
    exit $LASTEXITCODE
}
