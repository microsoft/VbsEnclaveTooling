// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_std]
extern crate alloc;

mod edl_impls;

use core::panic::PanicInfo;
use windows_enclave::vertdll::{
    ImageEnclaveConfig, IMAGE_ENCLAVE_FLAG_PRIMARY_IMAGE, IMAGE_ENCLAVE_MINIMUM_CONFIG_SIZE,
};

// A VBS enclave cannot unwind, so a panic simply halts the calling thread.
#[panic_handler]
fn panic(_panic: &PanicInfo<'_>) -> ! {
    loop {}
}

// Export the trusted enclave functions from the generated bindings.
tls_sample_enclave_gen::export_enclave_functions!(edl_impls::EnclaveImpl);

// Export the SDK enclave functions so the generated VTL0 callbacks can be
// dispatched.
vbsenclave_sdk_enclave::export_sdk_enclave_functions!();

pub const ENCLAVE_CONFIG_POLICY_FLAGS: u32 = {
    #[cfg(debug_assertions)]
    {
        windows_enclave::vertdll::IMAGE_ENCLAVE_POLICY_DEBUGGABLE
    }

    #[cfg(not(debug_assertions))]
    {
        0
    }
};

// Required for the enclave image to load.
#[unsafe(no_mangle)]
#[allow(non_upper_case_globals)]
pub static __enclave_config: ImageEnclaveConfig = ImageEnclaveConfig {
    size: size_of::<ImageEnclaveConfig>() as u32,
    minimum_required_config_size: IMAGE_ENCLAVE_MINIMUM_CONFIG_SIZE,
    policy_flags: ENCLAVE_CONFIG_POLICY_FLAGS,
    number_of_imports: 0,
    import_list: 0,
    import_entry_size: 0,
    family_id: [0xFE, 0xFE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    image_id: [
        0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ],
    image_version: 0,
    security_version: 0,
    enclave_size: 0x1000_0000,
    number_of_threads: 16,
    enclave_flags: IMAGE_ENCLAVE_FLAG_PRIMARY_IMAGE,
};

#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn DllMain(
    _instance: *const core::ffi::c_void,
    _reason: u32,
    _reserved: *mut core::ffi::c_void,
) -> bool {
    true
}
