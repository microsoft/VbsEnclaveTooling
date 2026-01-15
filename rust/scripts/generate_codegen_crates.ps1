# Generates the edlcodegen bindings for both host and enclave crates.

param(
    [Parameter(Mandatory = $true)]
    [string]$HostAppOutDir = "",

    [Parameter(Mandatory = $true)]
    [string]$EnclaveOutDir = "",

    [Parameter(Mandatory = $true)]
    [string]$EdlPath = "",

    [Parameter(Mandatory = $true)]
    [string]$Namespace = "",

    [string]$Vtl0ClassName = ""
)

$ErrorActionPreference = "Stop"

# Import helper that sets $edlCodeGenToolsPath
. "$PSScriptRoot\get_codegen_executable.ps1"

# Run codegen for the enclave crate
& $edlCodeGenToolsPath `
    --namespace $Namespace `
    --language rust `
    --EdlPath $EdlPath `
    --VirtualTrustLayer enclave `
    --OutputDirectory $EnclaveOutDir

# Run codegen for the host crate
& $edlCodeGenToolsPath `
    --namespace $Namespace `
    --language rust `
    --EdlPath $EdlPath `
    --VirtualTrustLayer hostapp `
    --Vtl0ClassName $Vtl0ClassName `
    --OutputDirectory $HostAppOutDir
