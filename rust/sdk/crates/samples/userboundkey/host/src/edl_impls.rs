// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-side implementation of EDL untrusted functions.

use userboundkey_sample_host_gen::AbiError;
use userboundkey_sample_host_gen::implementation::untrusted::Untrusted;

/// Implementation of the Untrusted trait for the sample
pub struct UntrustedImpl;

impl Untrusted for UntrustedImpl {
    /// Debug print function - prints to console from enclave
    fn debug_print(message: &String) -> Result<(), AbiError> {
        println!("[Enclave] {}", message);
        Ok(())
    }
}
