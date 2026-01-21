// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Generated trait for the trusted function declarations from the EDL file.
use test_enclave_gen::implementation::trusted::Trusted;
use test_enclave_gen::AbiError;
use test_enclave_gen::stubs::untrusted::print;
use alloc::string::ToString;
use tracelogging as tlg;
use crate::{HELLO_WORLD_PROVIDER};

pub struct EnclaveImpl{}

impl Trusted for EnclaveImpl {
    fn do_secret_math(val1: u32, val2: u32) -> Result<u32, AbiError> {
        tlg::write_event!(
            HELLO_WORLD_PROVIDER,                      // The provider to use for the event.
            "do_secret_math_invoked",                  // Event category bits.
            str8("Field1", "do_secret_math invoked!"), // Add a string field to the event.
        );
        
        // Print message to console from within the enclave.
        print(&"Performing secret math operation inside VTL1...".to_string())?;
        Ok(val1 + val2)
    }
}