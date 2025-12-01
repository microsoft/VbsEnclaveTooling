// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use test_enclave_gen::implementation::trusted::Trusted;
use test_enclave_gen::stubs::untrusted::print;
use alloc::string::ToString;

pub struct EnclaveImpl{}

impl Trusted for EnclaveImpl {
    fn do_secret_math(val1: u32, val2: u32) -> u32 {
        let _ = print(&"Performing secret math operation inside VTL1...".to_string());
        val1 + val2
    }
}