// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use test_host_gen::stubs::trusted::TestVtl0Host;
mod edl_impls;
use crate::edl_impls::HostImpl;
use vbsenclave_sdk_host::enclave::EnclaveHandle;
use vbsenclave_sdk_host::enclave;

const ENCLAVE_CREATE_INFO_FLAG: u32 = {
    #[cfg(debug_assertions)]
    { vbsenclave_sdk_host::enclave::ENCLAVE_CREATE_INFO_FLAG_DEBUG }

    #[cfg(not(debug_assertions))]
    { vbsenclave_sdk_host::enclave::ENCLAVE_CREATE_INFO_FLAG_RELEASE }
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting VBS Enclave HelloWorld Sample...");

    let enclave_handle = EnclaveHandle::create_and_initialize(
        "enclave.dll",
        enclave::megabytes(256),
        None,
        ENCLAVE_CREATE_INFO_FLAG,
    )?;

    let test_host = TestVtl0Host::new(enclave_handle.as_ptr());

    // Register the untrusted function implementations for the test enclave.
    if let Err(err) = test_host.register_vtl0_callbacks::<HostImpl>() {
        return Err(format!("Failed to register VTL0 callbacks: HRESULT: {:x}", err.to_hresult().0).into());
    }

    // Register SDK VTL0 callbacks to enable SDK features in the enclave.
    if let Err(err) = vbsenclave_sdk_host::register_sdk_callbacks(enclave_handle.as_ptr()) {
        return Err(format!("Failed to register SDK VTL0 callbacks: HRESULT: {:x}", err.to_hresult().0).into());
    }

    let secret_result = test_host.do_secret_math(42, 58);
    if let Err(err) = secret_result {
        return Err(format!("do_secret_math failed: HRESULT {:x}", err.to_hresult().0).into());
    }
    
    let secret_value = secret_result.unwrap();
    println!("do_secret_math returned: {}", secret_value);
    assert_eq!(secret_value, 100);

    Ok(())
}
