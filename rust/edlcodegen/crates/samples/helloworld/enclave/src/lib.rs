// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_std]
extern crate alloc;
mod edl_impls;
mod enclave_constants;
use enclave_constants::*;
use core::panic::PanicInfo;

// Developer creates their own panic handler for no_std environments.
// Note: The rust analyzer in VSCode shows red squiggly lines in the IDE.
// That said, the code still compiles and works correctly.
// To remove it add "rust-analyzer.check.allTargets": false in your
// VSCode -> Preferences: Open Workspace settings (JSON).
// See: https://github.com/rust-lang/rust-analyzer/issues/4490#issuecomment-3241437252
#[panic_handler]
fn panic(_panic: &PanicInfo<'_>) -> ! {
    loop {}
}

// Export the enclave functions using the macro from the generated
// test_enclave_gen crate.
test_enclave_gen::export_enclave_functions!(edl_impls::EnclaveImpl);

pub const ENCLAVE_CONFIG_POLICY_FLAGS: u32 = {
    // Enable debuggability of the enclave in debug builds.
    #[cfg(debug_assertions)]
    { IMAGE_ENCLAVE_POLICY_DEBUGGABLE }

    // Disable debuggability in release builds.
    #[cfg(not(debug_assertions))]
    { 0 } 
};

// This structure is necessary for the enclave to load correctly.
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
        0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
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
    _reserved: *mut core::ffi::c_void,) -> bool {
    true
}