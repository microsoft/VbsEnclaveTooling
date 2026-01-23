// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_std]
#![allow(dead_code)]
#![allow(non_snake_case)]

mod enclave_ffi;
use veil_abi_enclave_gen::export_enclave_functions;
extern crate alloc;
pub mod etw;

// Re-export Uuid from the uuid crate for use in enclave code.
pub use uuid::Uuid;

/// Developer should call this function in their dllmain to export the
/// SDK enclave functions.
#[inline(always)]
pub fn export_enclave_functions() {
    export_enclave_functions!(etw::EnclaveImpl);
}
