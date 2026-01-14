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
        panic!("Failed to register VTL0 callbacks: HRESULT: {:x}", err.to_hresult().0);
    }

    let secret_result = test_host.do_secret_math(42, 58);
    if let Err(err) = secret_result {
        panic!("do_secret_math failed: HRESULT {:x}", err.to_hresult().0);

    }
    
    let secret_value = secret_result.unwrap();
    println!("do_secret_math returned: {}", secret_value);
    assert_eq!(secret_value, 100);

    Ok(())
}
