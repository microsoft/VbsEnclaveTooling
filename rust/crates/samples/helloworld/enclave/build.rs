// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

fn main() {
    // Emits the linker arguments needed to build this crate as a VBS enclave.
    edlcodegen_tools::link_win_sdk_enclave_libs().unwrap();
}
