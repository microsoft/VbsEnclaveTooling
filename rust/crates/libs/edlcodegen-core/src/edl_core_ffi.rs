// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::edl_core_types::{AbiError, BOOL, WIN32_TRUE};
use core::ffi::c_void;

// The consuming crate will link these in based on which side of the trust boundary the crate exists
// in. Either Kernel32 for the host or vertdll for the enclave.
unsafe extern "system" {
    pub fn CallEnclave(
        lproutine: isize,
        lpparameter: *const c_void,
        fwaitforthread: i32,
        lpreturnvalue: *mut *mut c_void,
    ) -> i32;
    pub fn GetLastError() -> u32;
    pub fn GetProcessHeap() -> *mut c_void;
    pub fn HeapAlloc(hheap: *mut c_void, dwflags: u32, dwbytes: usize) -> *mut c_void;
    pub fn HeapFree(hheap: *mut c_void, dwflags: u32, lpmem: *const c_void) -> i32;
}

/// Safely calls the `CallEnclave` Win32 API.
///
/// # Safety
/// Rust cannot guarantee the validity, alignment, or lifetime of the pointers involved.
/// The caller must ensure:
/// - `func` points to a valid function.
/// - The function pointer adheres to the expected ABI:
///   `extern "system" fn(*mut c_void) -> *mut c_void`.
pub unsafe fn call_enclave(
    func: isize,
    in_param: *const c_void,
    out_param: *mut *mut c_void,
) -> Result<(), AbiError> {
    let func_res = unsafe { BOOL(CallEnclave(func, in_param, WIN32_TRUE.0, out_param)) };
    if !func_res.as_bool() {
        let last_err = unsafe { GetLastError() };
        return Err(AbiError::Win32Error(last_err));
    }
    Ok(())
}
