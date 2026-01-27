// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Common utilities and SDK implementations for VTL0 host operations.

pub mod sdk_impls;

pub use sdk_impls::HostImpl;

/// Print a message from the enclave to the host's standard output.
pub fn enclave_println(msg: &String) {
    println!("[Enclave] {}", msg);
}
