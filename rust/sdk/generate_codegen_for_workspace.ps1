# Generates EDL code bindings for the entire SDK workspace.
#
# This script generates Rust bindings from EDL files for:
# - SDK core libraries (sdk namespace)
# - Sample applications (userboundkey_sample)
#
# Use this script when:
# - Working on EDL interface definitions
# - Need updated IntelliSense after EDL changes
# - Want fast iteration without full compilation
#
# The generated bindings are automatically formatted with rustfmt.

$errorActionPreference = "Stop"

# Locate shared scripts folder
. "$PSScriptRoot\..\scripts\get_common_paths.ps1"

# SDK crate paths
$enclaveSdkCrate = Join-Path $SdkWorkspacePath "crates/libs/sdk-enclave"
$hostSdkCrate    = Join-Path $SdkWorkspacePath "crates/libs/sdk-host"
$importDir = Join-Path $SdkWorkspacePath "crates/libs/edl/"

# Generate SDK EDL bindings (user-bound key APIs and other SDK features)
$sdkEdl = Join-Path $SdkWorkspacePath "crates\libs\sdk.edl"
. "$scriptsDir\generate_codegen_crates.ps1" `
    -HostAppOutDir "$hostSdkCrate\generated" `
    -EnclaveOutDir "$enclaveSdkCrate\generated" `
    -EdlPath $sdkEdl `
    -Namespace "sdk" `
    -Vtl0ClassName "SdkHost"

# Generate sample EDL bindings (userboundkey sample application interface)
$sampleDir = Join-Path $SdkWorkspacePath "crates\samples\userboundkey"
$sampleEdl = Join-Path $sampleDir "userboundkey_sample.edl"
$libsImportDir = Join-Path $SdkWorkspacePath "crates\libs"

. "$scriptsDir\generate_codegen_crates.ps1" `
    -HostAppOutDir "$sampleDir\host\generated" `
    -EnclaveOutDir "$sampleDir\enclave\generated" `
    -EdlPath $sampleEdl `
    -Namespace "userboundkey_sample" `
    -ImportDir $libsImportDir `
    -Vtl0ClassName "UntrustedImpl"

# Format SDK workspace
. "$scriptsDir\invoke_rustfmt_workspace.ps1" -WorkspacePath $PSScriptRoot

# Format sample workspace (now in its own workspace)
. "$scriptsDir\invoke_rustfmt_workspace.ps1" -WorkspacePath $sampleDir