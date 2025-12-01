# Generates the host and enclave Rust crates from the sample EDL file and then
# builds them with cargo to validate the generated code. It also optionally provisions
# the enclave DLL with veiid.exe and signs it with signtool if a cert name is
# provided.

param(
    [ValidateSet("debug", "release")]
    [string]$Configuration = "debug",

    [string]$CertName = ""
)

$errorActionPreference = "Stop"

# Locate shared scripts folder
$scriptsDir = Resolve-Path "$PSScriptRoot\..\..\scripts"

# Import helper that sets $edlCodeGenToolsPath
. "$scriptsDir\get_codegen_executable.ps1"

# Common paths
$edlPath      = Join-Path $PSScriptRoot "test.edl"
$enclaveCrate = Join-Path $PSScriptRoot "enclave"
$hostCrate    = Join-Path $PSScriptRoot "host"

# Run codegen for enclave and host crates
& $edlCodeGenToolsPath `
    --namespace test `
    --language rust `
    --EdlPath $edlPath `
    --VirtualTrustLayer enclave `
    --OutputDirectory "$enclaveCrate\generated"

& $edlCodeGenToolsPath `
    --namespace test `
    --language rust `
    --EdlPath $edlPath `
    --VirtualTrustLayer hostapp `
    --Vtl0ClassName TestVtl0Host `
    --OutputDirectory "$hostCrate\generated"

# Build both crates
& "$scriptsDir\invoke_cargo_build.ps1" -Path $enclaveCrate -Configuration $Configuration
& "$scriptsDir\invoke_cargo_build.ps1" -Path $hostCrate -Configuration $Configuration

# Make sure enclave DLL is provisioned and signed if cert name provided
$dllPath = "$PSScriptRoot\target\$Configuration\enclave.dll"
& "$scriptsDir\sign-enclave.ps1" -DllPath $dllPath -CertName $CertName
