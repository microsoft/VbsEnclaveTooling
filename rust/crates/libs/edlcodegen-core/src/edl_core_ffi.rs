#![allow(non_camel_case_types, non_snake_case, unused_imports)]
use crate::edl_core_types::AbiError;
use core::ffi::c_void;

// The following subset of types/consts were taken from the windows_sys::Win32::Foundation.
// We need to make sure that this crate can be usable in both the host and the enclave
// and not accidentally bring in things that are not usable inside an enclave.
pub type EnclaveRoutine = isize;
pub type AbiFuncPtr = unsafe extern "system" fn(*mut c_void) -> *mut c_void;
pub type HANDLE = *mut core::ffi::c_void;
pub type HEAP_FLAGS = u32;
pub type WIN32_ERROR = u32;
pub type WIN32_BOOL = i32;
pub const HEAP_ZERO_MEMORY: HEAP_FLAGS = 8u32;
pub const S_OK: i32 = 0x0_u32 as _;
pub const E_FAIL: i32 = 0x80004005_u32 as _;
pub const E_INVALIDARG: i32 = 0x80070057_u32 as _;

// Taken from the windows_result crate. That crate links in kernel32.dll
// as dependency which we don't want here, since this crate is used in both
// the host and the enclave.
pub const TRUE: BOOL = BOOL(1);
pub const FALSE: BOOL = BOOL(0);
#[derive(Clone, Copy)]
pub struct BOOL(pub i32);
impl BOOL {
    #[inline]
    pub fn as_bool(self) -> bool {
        self.0 != 0
    }
}

// Taken from the windows_result crate. That crate links in kernel32.dll
// as dependency which we don't want here, since this crate is used in both
// the host and the enclave.
#[derive(Clone, Copy)]
pub struct HRESULT(pub i32);
impl HRESULT {
    pub const fn from_win32(error: u32) -> Self {
        Self(if error as i32 <= 0 {
            error
        } else {
            (error & 0x0000_FFFF) | (7 << 16) | 0x8000_0000
        } as i32)
    }
}

// The consuming crate will link these in based on which side of the trust boundary the crate exists
// in. Either Kernel32 for the host or vertdll for the enclave.
unsafe extern "system" {
    pub fn CallEnclave(
        lproutine: isize,
        lpparameter: *const c_void,
        fwaitforthread: WIN32_BOOL,
        lpreturnvalue: *mut *mut c_void,
    ) -> WIN32_BOOL;
    pub fn GetLastError() -> WIN32_ERROR;
    pub fn GetProcessHeap() -> HANDLE;
    pub fn HeapAlloc(hheap: HANDLE, dwflags: HEAP_FLAGS, dwbytes: usize) -> *mut c_void;
    pub fn HeapFree(
        hheap: HANDLE,
        dwflags: HEAP_FLAGS,
        lpmem: *const c_void,
    ) -> WIN32_BOOL;
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
        unsafe { BOOL(CallEnclave(func, in_param, TRUE.0, out_param)) };
    if !func_res.as_bool() {
        let last_err = unsafe { GetLastError() };
        return Err(AbiError::Win32Error(last_err));
    }
    Ok(())
}
