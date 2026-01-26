// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! VBS Enclave for User-Bound Key Sample
//!
//! This enclave demonstrates how to use the VBS enclave SDK's user-bound key
//! functionality with Windows Hello protection.

#![no_std]
extern crate alloc;

mod edl_impls;

use core::panic::PanicInfo;

#[allow(unused_imports)]
use windows_enclave::vertdll::{
    IMAGE_ENCLAVE_FLAG_PRIMARY_IMAGE, IMAGE_ENCLAVE_MINIMUM_CONFIG_SIZE,
    IMAGE_ENCLAVE_POLICY_DEBUGGABLE, ImageEnclaveConfig,
};

// Panic handler for no_std environment
#[panic_handler]
fn panic(_panic: &PanicInfo<'_>) -> ! {
    loop {}
}

// Export the sample's enclave functions (CreateUserBoundKey, LoadUserBoundKeyAndEncryptData, etc.)
userboundkey_sample_enclave_gen::export_enclave_functions!(edl_impls::EnclaveImpl);

// Export the SDK's enclave functions (userboundkey callbacks, attestation, etc.)
// This single macro call handles all SDK features and hides internal implementation details.
vbsenclave_sdk_enclave::export_sdk_enclave_functions!();

/// Enclave policy flags - enable debugging in debug builds
pub const ENCLAVE_CONFIG_POLICY_FLAGS: u32 = {
    #[cfg(debug_assertions)]
    {
        IMAGE_ENCLAVE_POLICY_DEBUGGABLE
    }
    #[cfg(not(debug_assertions))]
    {
        0
    }
};

/// Enclave configuration structure required for VBS enclave loading.
/// This must be present and correctly configured for the enclave to load.
#[unsafe(no_mangle)]
#[allow(non_upper_case_globals)]
pub static __enclave_config: ImageEnclaveConfig = ImageEnclaveConfig {
    size: core::mem::size_of::<ImageEnclaveConfig>() as u32,
    minimum_required_config_size: IMAGE_ENCLAVE_MINIMUM_CONFIG_SIZE,
    policy_flags: ENCLAVE_CONFIG_POLICY_FLAGS,
    number_of_imports: 0,
    import_list: 0,
    import_entry_size: 0,
    // Family ID - unique to your application family
    family_id: [0xFE, 0xFE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    // Image ID - unique to this specific enclave
    image_id: [
        0x55, 0x42, 0x4B, 0x53, // "UBKS" - User Bound Key Sample
        0x00, 0x01, 0x00, 0x00, // Version 0.1.0.0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ],
    image_version: 1,
    security_version: 1,
    enclave_size: 0x2000_0000, // 512 MB - must match host's create request
    number_of_threads: 16,
    enclave_flags: IMAGE_ENCLAVE_FLAG_PRIMARY_IMAGE,
};

/// DLL entry point - required for the enclave DLL.
#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "system" fn DllMain(
    _dll_handle: *const core::ffi::c_void,
    _reason: u32,
    _reserved: *mut core::ffi::c_void,
) -> bool {
    true
}
