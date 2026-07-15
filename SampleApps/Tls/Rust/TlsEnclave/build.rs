// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Emits the linker arguments needed to build this crate as a VBS enclave.
    edlcodegen_tools::set_enclave_linker_flags();
    edlcodegen_tools::link_win_sdk_enclave_libs()?;
    Ok(())
}
