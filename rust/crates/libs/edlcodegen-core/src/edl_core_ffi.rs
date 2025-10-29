#![allow(non_camel_case_types, non_snake_case, unused_imports)]
use crate::edl_core_types::AbiError;
use core::ffi::c_void;

// The following subset of types/consts were taken from the windows_sys::Win32::Foundation.
// We need to make sure that this crate can be usable in both the host and the enclave
// and not accidentally bring in things that are not usable inside an enclave.
pub type EnclaveRoutine = isize;
pub type HANDLE = *mut core::ffi::c_void;
pub type HEAP_FLAGS = u32;
pub type WIN32_ERROR = u32;
pub const HEAP_ZERO_MEMORY: HEAP_FLAGS = 8u32;
pub const TRUE: windows_sys::core::BOOL = 1i32;
pub const FALSE: windows_sys::core::BOOL = 0i32;
pub const S_OK: windows_sys::core::HRESULT = 0x0_u32 as _;
pub const E_FAIL: windows_sys::core::HRESULT = 0x80004005_u32 as _;
pub const E_INVALIDARG: windows_sys::core::HRESULT = 0x80070057_u32 as _;
pub static WIN32_FALSE: windows_result::BOOL = windows_result::BOOL(FALSE);
pub static WIN32_TRUE: windows_result::BOOL = windows_result::BOOL(TRUE);

// The consuming crate will link these in based on which side of the trust boundary the crate exists
// in. Either Kernel32 for the host or vertdll for the enclave.
unsafe extern "system" {
    pub fn CallEnclave(
        lproutine: isize,
        lpparameter: *const c_void,
        fwaitforthread: windows_sys::core::BOOL,
        lpreturnvalue: *mut *mut c_void,
    ) -> windows_sys::core::BOOL;

    pub fn GetLastError() -> WIN32_ERROR;
    pub fn GetProcessHeap() -> HANDLE;
    pub fn HeapAlloc(hheap: HANDLE, dwflags: HEAP_FLAGS, dwbytes: usize) -> *mut c_void;
    pub fn HeapFree(
        hheap: HANDLE,
        dwflags: HEAP_FLAGS,
        lpmem: *const c_void,
    ) -> windows_sys::core::BOOL;
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
    let func_res =
        unsafe { windows_result::BOOL(CallEnclave(func, in_param, WIN32_TRUE.0, out_param)) };

    if !func_res.as_bool() {
        let last_err = unsafe { GetLastError() };
        return Err(AbiError::Win32Error(last_err));
    }

    Ok(())
}
