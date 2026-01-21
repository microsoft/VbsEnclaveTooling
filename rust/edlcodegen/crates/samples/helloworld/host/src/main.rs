// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use test_host_gen::stubs::trusted::TestVtl0Host;
mod edl_impls;
mod enclave_api_ffi;
mod container;
use crate::container::EnclaveContainer;
use crate::edl_impls::HostImpl;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting VBS Enclave HelloWorld Sample...");

    let enclave_container = EnclaveContainer::new()?;
    let test_host = TestVtl0Host::new(enclave_container.enclave);

    if let Err(err) = test_host.register_vtl0_callbacks::<HostImpl>() {
        return Err(format!("Failed to register VTL0 callbacks: HRESULT: {:x}", err.to_hresult().0).into());
    }

    if let Err(err) = vbsenclave_sdk_host::register_sdk_callbacks(enclave_container.enclave) {
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
