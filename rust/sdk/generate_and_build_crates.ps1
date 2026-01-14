# Generates the edlcodegen bindings for the host and enclave sdk crates from
# the veil_abi EDL file and builds the sdk workspace.

param(
    [ValidateSet("debug", "release")]
    [string]$Configuration = "debug"
)

$errorActionPreference = "Stop"

# Locate shared scripts folder
. "$PSScriptRoot\..\scripts\get_common_paths.ps1"

# Generate edlcodegen crates for the workspace first before attempting
# to build the sdk workspace.
. "$PSScriptRoot\generate_codegen_for_workspace.ps1"

# Build the sdk workspace now that codegeneration is completed.
. "$scriptsDir\invoke_cargo_build.ps1" -Path $PSScriptRoot -Configuration $Configuration

