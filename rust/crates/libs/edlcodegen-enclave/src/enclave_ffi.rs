// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::win_enclave_bindings::{
    ENCLAVE_INFORMATION, EnclaveCopyIntoEnclave, EnclaveCopyOutOfEnclave,
    EnclaveGetEnclaveInformation, EnclaveRestrictContainingProcessAccess,
};

use core::{ffi::c_void, mem};

#[allow(unused_imports)]
use edlcodegen_core::edl_core_ffi::{S_OK, WIN32_FALSE, WIN32_TRUE};
use edlcodegen_core::edl_core_types::AbiError;
use spin::Once;

#[cfg(not(debug_assertions))]
const SHOULD_RESTRICT_ACCESS: windows_result::BOOL = WIN32_TRUE; // for release

#[cfg(debug_assertions)]
const SHOULD_RESTRICT_ACCESS: windows_result::BOOL = WIN32_FALSE; // for debug

#[allow(dead_code)]
pub fn enable_enclave_restrict_containing_process_access_once() {
    static ENCLAVE_RESTRICT_ACCESS_INIT: Once<()> = Once::new();
    ENCLAVE_RESTRICT_ACCESS_INIT.call_once(|| unsafe {
        let mut prev_restriction: i32 = S_OK;
        let prev_restriction_ptr: *mut i32 = &mut prev_restriction;

        let hr =
            EnclaveRestrictContainingProcessAccess(SHOULD_RESTRICT_ACCESS.0, prev_restriction_ptr);

        if hr != S_OK {
            panic!("Enabling strict memory access failed with {:X}", hr);
        }
    });
}

/// Safely copy data **into** the enclave address space.
///
/// Wraps `EnclaveCopyIntoEnclave(dst, src, size)`.
pub fn enclave_copy_into_enclave<T>(dst: &mut T, src: *const T) -> Result<(), AbiError> {
    let hr = unsafe {
        EnclaveCopyIntoEnclave(
            dst as *mut _ as *mut c_void,
            src as *const c_void,
            mem::size_of::<T>(),
        )
    };

    if hr == S_OK {
        Ok(())
    } else {
        Err(AbiError::Hresult(hr))
    }
}

/// Safely copy data **out of** the enclave into the host.
///
/// Wraps `EnclaveCopyOutOfEnclave(dst, src, size)`.
pub fn enclave_copy_out_of_enclave<T>(dst: *mut T, src: *const T) -> Result<(), AbiError> {
    let hr = unsafe {
        EnclaveCopyOutOfEnclave(
            dst as *mut c_void,
            src as *const c_void,
            mem::size_of::<T>(),
        )
    };

    if hr == S_OK {
        Ok(())
    } else {
        Err(AbiError::Hresult(hr))
    }
}

/// Copy an arbitrary buffer (e.g., FlatBuffer payload) **out of** the enclave.
///
/// This is used for transferring serialized data or large payloads to VTL0 memory.
pub fn enclave_copy_buffer_out(dst: *mut u8, src: *const u8, size: usize) -> Result<(), AbiError> {
    let hr = unsafe { EnclaveCopyOutOfEnclave(dst as *mut c_void, src as *const c_void, size) };

    if hr == S_OK {
        Ok(())
    } else {
        Err(AbiError::Hresult(hr))
    }
}

/// Copy an arbitrary buffer (e.g., FlatBuffer payload) **into** the enclave.
///
/// This is used when VTL0 passes a serialized payload to the enclave.
pub fn enclave_copy_buffer_in(dst: *mut u8, src: *const u8, size: usize) -> Result<(), AbiError> {
    let hr = unsafe { EnclaveCopyIntoEnclave(dst as *mut c_void, src as *const c_void, size) };

    if hr == S_OK {
        Ok(())
    } else {
        Err(AbiError::Hresult(hr))
    }
}

/// Safely retrieves enclave information using the `EnclaveGetEnclaveInformation` Win32 API.
pub fn enclave_get_enclave_information() -> Result<ENCLAVE_INFORMATION, AbiError> {
    let mut info = ENCLAVE_INFORMATION::default();

    let hr = unsafe {
        EnclaveGetEnclaveInformation(mem::size_of::<ENCLAVE_INFORMATION>() as u32, &mut info)
    };

    if hr == S_OK {
        Ok(info)
    } else {
        Err(AbiError::Hresult(hr))
    }
}
