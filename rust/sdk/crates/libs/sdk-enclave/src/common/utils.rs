// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Utility functions for VTL1 enclave operations
//!
//! This module provides general-purpose utilities for enclave operations
//! that can be used across different SDK modules.

use core::mem;
use spin::Once;

use windows_enclave::vertdll::{
    ENCLAVE_FLAG_DYNAMIC_DEBUG_ACTIVE, ENCLAVE_FLAG_DYNAMIC_DEBUG_ENABLED,
    ENCLAVE_FLAG_FULL_DEBUG_ENABLED, ENCLAVE_INFORMATION, EnclaveGetEnclaveInformation,
    RtlNtStatusToDosError,
};

/// Common error type for enclave utility operations
#[derive(Debug, Clone, Copy)]
pub enum EnclaveUtilsError {
    /// Windows HRESULT error
    Hresult(i32),
}

impl EnclaveUtilsError {
    /// Convert to HRESULT for compatibility
    pub fn to_hresult(self) -> i32 {
        match self {
            EnclaveUtilsError::Hresult(hr) => hr,
        }
    }
}

/// Wrapper for ENCLAVE_INFORMATION that implements Send + Sync.
/// SAFETY: The BaseAddress pointer is read-only after initialization
/// and points to enclave memory which is valid for the enclave's lifetime.
#[derive(Clone, Copy)]
struct SyncEnclaveInfo(ENCLAVE_INFORMATION);

// SAFETY: ENCLAVE_INFORMATION contains a *mut c_void (BaseAddress) but:
// 1. It's effectively read-only after initialization
// 2. It points to enclave memory mapped for the process lifetime
// 3. We only ever read from it, never write through it
unsafe impl Send for SyncEnclaveInfo {}
unsafe impl Sync for SyncEnclaveInfo {}

/// Cached enclave information (initialized once)
static ENCLAVE_INFO: Once<Result<SyncEnclaveInfo, EnclaveUtilsError>> = Once::new();

/// Get enclave information, initializing and caching it on first access.
///
/// - Thread-safe
/// - No heap allocation
/// - No atomic pointer management
/// - Error is cached to avoid repeated syscalls
pub fn get_enclave_information() -> Result<ENCLAVE_INFORMATION, EnclaveUtilsError> {
    ENCLAVE_INFO
        .call_once(|| {
            let mut info: ENCLAVE_INFORMATION = unsafe { mem::zeroed() };

            let hr = unsafe {
                EnclaveGetEnclaveInformation(
                    mem::size_of::<ENCLAVE_INFORMATION>() as u32,
                    &mut info,
                )
            };

            if hr < 0 {
                return Err(EnclaveUtilsError::Hresult(hr));
            }

            Ok(SyncEnclaveInfo(info))
        })
        .as_ref()
        .map(|s| s.0)
        .map_err(|e| *e)
}

/// Get the base address of the enclave
///
/// Returns the enclave's base address as a pointer, suitable for passing
/// to APIs that require an enclave identifier.
pub fn get_enclave_base_address() -> Result<*mut core::ffi::c_void, EnclaveUtilsError> {
    let info = get_enclave_information()?;
    Ok(info.BaseAddress)
}

/// Get the base address of the enclave as a u64
///
/// Convenience function that returns the base address as a u64,
/// suitable for EDL interface calls.
pub fn get_enclave_base_address_u64() -> Result<u64, EnclaveUtilsError> {
    Ok(get_enclave_base_address()? as u64)
}

/// Check if full debug is enabled for the enclave
#[allow(dead_code)]
pub fn is_enclave_full_debug_enabled() -> Result<bool, EnclaveUtilsError> {
    let info = get_enclave_information()?;
    Ok((info.Identity.Flags & ENCLAVE_FLAG_FULL_DEBUG_ENABLED) != 0)
}

/// Check if dynamic debug is enabled for the enclave
#[allow(dead_code)]
pub fn is_enclave_dynamic_debug_enabled() -> Result<bool, EnclaveUtilsError> {
    let info = get_enclave_information()?;
    Ok((info.Identity.Flags & ENCLAVE_FLAG_DYNAMIC_DEBUG_ENABLED) != 0)
}

/// Check if dynamic debug is currently active for the enclave
#[allow(dead_code)]
pub fn is_enclave_dynamic_debug_active() -> Result<bool, EnclaveUtilsError> {
    let info = get_enclave_information()?;
    Ok((info.Identity.Flags & ENCLAVE_FLAG_DYNAMIC_DEBUG_ACTIVE) != 0)
}

/// Converts a Win32 error code to an HRESULT.
/// Equivalent to the HRESULT_FROM_WIN32 macro.
#[inline]
pub fn hresult_from_win32(error: u32) -> i32 {
    if error == 0 {
        0 // S_OK
    } else {
        // FACILITY_WIN32 = 7, so (7 << 16) | 0x80000000 = 0x80070000
        ((error & 0x0000FFFF) | 0x80070000) as i32
    }
}

/// Convert NTSTATUS to HRESULT using RtlNtStatusToDosError
pub fn ntstatus_to_hresult(ntstatus: i32) -> i32 {
    // SAFETY: RtlNtStatusToDosError is a pure function that converts NTSTATUS to Win32 error
    let win32_error = unsafe { RtlNtStatusToDosError(ntstatus) };
    if win32_error == 0 {
        0 // S_OK
    } else {
        hresult_from_win32(win32_error)
    }
}
