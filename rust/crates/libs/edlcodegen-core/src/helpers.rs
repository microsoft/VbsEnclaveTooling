// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::{
    edl_core_ffi::{
        E_FAIL, E_INVALIDARG, GetProcessHeap, HEAP_ZERO_MEMORY, HeapAlloc, HeapFree, S_OK,
    },
    edl_core_types::AbiError,
};
use core::ffi::c_void;

pub fn abi_func_to_address(func_ptr: extern "system" fn(*mut c_void) -> *mut c_void) -> u64 {
    func_ptr as *const () as u64
}

pub fn proc_address_to_isize(
    func_ptr: unsafe extern "system" fn(*mut c_void) -> *mut c_void,
) -> isize {
    func_ptr as *const () as isize
}

#[inline(always)]
pub fn hresult_to_pvoid(hr: i32) -> *mut c_void {
    ((hr as u64) & 0x0000_0000_FFFF_FFFF) as usize as *mut c_void
}

#[inline(always)]
pub fn pvoid_to_hresult(ptr: *mut c_void) -> i32 {
    ((ptr as u64) & 0x0000_0000_FFFF_FFFF) as i32
}

pub fn allocate_memory(size: usize) -> *mut c_void {
    unsafe { HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size) }
}

pub fn deallocate_memory(mem: *mut c_void) -> windows_result::HRESULT {
    if mem.is_null() {
        return windows_result::HRESULT(S_OK);
    }

    let res = unsafe { windows_result::BOOL(HeapFree(GetProcessHeap(), 0, mem as *const c_void)) };

    if !res.as_bool() {
        return windows_result::HRESULT(E_FAIL);
    }

    windows_result::HRESULT(S_OK)
}

/// A allocation function that can be called via `CallEnclave`.
#[unsafe(no_mangle)]
pub extern "system" fn allocate_memory_ffi(context: *mut c_void) -> *mut c_void {
    allocate_memory(context as usize)
}

/// A deallocation function that can be called via `CallEnclave`.
#[unsafe(no_mangle)]
pub extern "system" fn deallocate_memory_ffi(memory: *mut c_void) -> *mut c_void {
    let hr = deallocate_memory(memory);
    hr.0 as *mut c_void
}

/// Performs a raw memory copy from a Rust slice into a raw buffer.
pub fn copy_slice_to_buffer<T>(buffer: *mut c_void, data: &[T]) -> Result<(), AbiError> {
    if buffer.is_null() {
        return Err(AbiError::Hresult(E_INVALIDARG));
    }

    // SAFETY: caller guarantees buffer is valid and non-overlapping
    unsafe {
        core::ptr::copy_nonoverlapping(data.as_ptr(), buffer as *mut T, data.len());
    }

    Ok(())
}

#[macro_export]
macro_rules! return_hr_as_pvoid {
    ($result:expr) => {{
        if let Some(err) = $result.err() {
            return $crate::helpers::hresult_to_pvoid(err.to_hresult().0);
        }

        return $crate::edl_core_ffi::S_OK as *mut core::ffi::c_void;
    }};
}
