# Generates the edlcodegen bindings for all host and enclave sdk crates.

$errorActionPreference = "Stop"

# Locate shared scripts folder
. "$PSScriptRoot\..\scripts\get_common_paths.ps1"

# SDK crate paths
$edlPath      = Join-Path $repoRoot "src\VbsEnclaveSDK\veil_abi.edl"
$enclaveSdkCrate = Join-Path $SdkWorkspacePath "crates/libs/sdk-enclave"
$hostSdkCrate    = Join-Path $SdkWorkspacePath "crates/libs/sdk-host"

# Generate edlcodegen crates for the sdk-host and sdk-enclave crates 
. "$scriptsDir\generate_codegen_crates.ps1" `
    -HostAppOutDir "$hostSdkCrate\generated" `
    -EnclaveOutDir "$enclaveSdkCrate\generated" `
    -EdlPath $edlPath `
    -Namespace "veil_abi" `
    -Vtl0ClassName "export_interface"

# Generate userboundkey-specific EDL crates
$userboundkeyEdlPath = Join-Path $SdkWorkspacePath "crates\libs\userboundkey.edl"
. "$scriptsDir\generate_codegen_crates.ps1" `
    -HostAppOutDir "$hostSdkCrate\generated" `
    -EnclaveOutDir "$enclaveSdkCrate\generated" `
    -EdlPath $userboundkeyEdlPath `
    -Namespace "userboundkey" `
    -Vtl0ClassName "UserBoundKeyVtl0Host"

# Below this comment, Call the generate_codegen_crates.ps1 script
# on any other crates in the sdk workspace that need codegen bindings.
# E.g for any sample crates.

# Format the workspace after code generation to make sure all generated code
# is properly formatted.
. "$scriptsDir\invoke_rustfmt_workspace.ps1" -WorkspacePath $PSScriptRoot