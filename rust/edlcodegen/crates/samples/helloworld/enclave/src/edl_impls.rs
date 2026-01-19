// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Generated trait for the trusted function declarations from the EDL file.
use test_enclave_gen::implementation::trusted::Trusted;
use test_enclave_gen::AbiError;
use test_enclave_gen::stubs::untrusted::print;

pub struct EnclaveImpl{}

impl Trusted for EnclaveImpl {
    fn do_secret_math(val1: u32, val2: u32) -> Result<u32, AbiError> {
        print("Performing secret math operation inside VTL1...")?;
        Ok(val1 + val2)
    }
}