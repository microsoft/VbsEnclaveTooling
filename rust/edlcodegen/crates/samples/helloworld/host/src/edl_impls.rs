// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Generated trait for the untrusted function declarations from the EDL file.
use test_host_gen::implementation::untrusted::Untrusted;
use test_host_gen::AbiError;

pub struct HostImpl{}

impl Untrusted for HostImpl {
    fn print(data: &str) -> Result<(), AbiError> {
        println!("{}", data);
        Ok(())
    }
}
