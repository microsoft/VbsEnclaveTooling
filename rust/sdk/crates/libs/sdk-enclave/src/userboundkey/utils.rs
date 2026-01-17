// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Utility functions for VTL1 enclave operations
//!
//! This module provides general-purpose utilities for enclave operations,
//! similar to utils.vtl1.h in the C++ implementation.

use core::sync::atomic::{AtomicPtr, Ordering};

use windows_enclave::vertdll::{
    EnclaveGetEnclaveInformation, ENCLAVE_FLAG_DYNAMIC_DEBUG_ACTIVE,
    ENCLAVE_FLAG_DYNAMIC_DEBUG_ENABLED, ENCLAVE_FLAG_FULL_DEBUG_ENABLED, ENCLAVE_INFORMATION,
};

use super::types::UserBoundKeyError;

/// Static storage for cached enclave information
static ENCLAVE_INFO_CACHE: AtomicPtr<ENCLAVE_INFORMATION> = AtomicPtr::new(core::ptr::null_mut());

/// Get enclave information, caching it on first access
///
/// This function retrieves the enclave information from the system on first call
/// and caches it for subsequent calls, similar to `veil::vtl1::enclave_information()`.
pub fn get_enclave_information() -> Result<&'static ENCLAVE_INFORMATION, UserBoundKeyError> {
    // Check if already cached
    let ptr = ENCLAVE_INFO_CACHE.load(Ordering::Acquire);
    if !ptr.is_null() {
        return Ok(unsafe { &*ptr });
    }

    // Allocate and initialize
    // We use a Box that we leak to get a 'static reference
    let mut info: ENCLAVE_INFORMATION = unsafe { core::mem::zeroed() };

    let hr = unsafe {
        EnclaveGetEnclaveInformation(
            core::mem::size_of::<ENCLAVE_INFORMATION>() as u32,
            &mut info,
        )
    };

    if hr < 0 {
        return Err(UserBoundKeyError::Hresult(hr));
    }

    // Leak the box to get a 'static pointer
    let boxed = alloc::boxed::Box::new(info);
    let new_ptr = alloc::boxed::Box::into_raw(boxed);

    // Try to set the cache (compare-and-swap)
    match ENCLAVE_INFO_CACHE.compare_exchange(
        core::ptr::null_mut(),
        new_ptr,
        Ordering::Release,
        Ordering::Acquire,
    ) {
        Ok(_) => {
            // We successfully set the cache
            Ok(unsafe { &*new_ptr })
        }
        Err(existing) => {
            // Another thread beat us - free our allocation and use theirs
            unsafe {
                let _ = alloc::boxed::Box::from_raw(new_ptr);
            }
            Ok(unsafe { &*existing })
        }
    }
}

/// Get the base address of the enclave
///
/// Returns the enclave's base address as a pointer, suitable for passing
/// to APIs that require an enclave identifier.
pub fn get_enclave_base_address() -> Result<*mut core::ffi::c_void, UserBoundKeyError> {
    let info = get_enclave_information()?;
    Ok(info.BaseAddress)
}

/// Get the base address of the enclave as a u64
///
/// Convenience function that returns the base address as a u64,
/// suitable for EDL interface calls.
pub fn get_enclave_base_address_u64() -> Result<u64, UserBoundKeyError> {
    Ok(get_enclave_base_address()? as u64)
}

/// Check if full debug is enabled for the enclave
#[allow(dead_code)]
pub fn is_enclave_full_debug_enabled() -> Result<bool, UserBoundKeyError> {
    let info = get_enclave_information()?;
    Ok((info.Identity.Flags & ENCLAVE_FLAG_FULL_DEBUG_ENABLED) != 0)
}

/// Check if dynamic debug is enabled for the enclave
#[allow(dead_code)]
pub fn is_enclave_dynamic_debug_enabled() -> Result<bool, UserBoundKeyError> {
    let info = get_enclave_information()?;
    Ok((info.Identity.Flags & ENCLAVE_FLAG_DYNAMIC_DEBUG_ENABLED) != 0)
}

/// Check if dynamic debug is currently active for the enclave
#[allow(dead_code)]
pub fn is_enclave_dynamic_debug_active() -> Result<bool, UserBoundKeyError> {
    let info = get_enclave_information()?;
    Ok((info.Identity.Flags & ENCLAVE_FLAG_DYNAMIC_DEBUG_ACTIVE) != 0)
}
