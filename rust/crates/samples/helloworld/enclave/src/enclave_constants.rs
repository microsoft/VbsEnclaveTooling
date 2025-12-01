// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Temporary: The contents of this file should be provided by the future
// windows-enclave crate. For now, we define the necessary constants and
// structs here.

#[allow(dead_code)] // debug policy not used in release builds
pub const IMAGE_ENCLAVE_POLICY_DEBUGGABLE: u32 = 0x0000_0001;
pub const IMAGE_ENCLAVE_SHORT_ID_LENGTH: usize = 16;
pub const IMAGE_ENCLAVE_FLAG_PRIMARY_IMAGE: u32 = 0x0000_0001;

// See: https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_enclave_config64
#[repr(C)]
pub struct ImageEnclaveConfig {
    pub size: u32,
    pub minimum_required_config_size: u32,
    pub policy_flags: u32,
    pub number_of_imports: u32,
    pub import_list: u32,
    pub import_entry_size: u32,
    pub family_id: [u8; IMAGE_ENCLAVE_SHORT_ID_LENGTH],
    pub image_id: [u8; IMAGE_ENCLAVE_SHORT_ID_LENGTH],
    pub image_version: u32,
    pub security_version: u32,
    pub enclave_size: usize,
    pub number_of_threads: u32,
    pub enclave_flags: u32,
}

pub const IMAGE_ENCLAVE_MINIMUM_CONFIG_SIZE: u32 =
    core::mem::offset_of!(ImageEnclaveConfig, enclave_flags) as u32;
