// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::edl_core_types::{AbiError, BOOL, S_OK, WIN32_TRUE};
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

pub struct CallEnclaveInput {
    func: isize,
    in_params_ptr: *const c_void,
}

impl CallEnclaveInput {
    pub const fn new(func: isize, ptr: *const c_void) -> Self {
        Self {
            func,
            in_params_ptr: ptr,
        }
    }
}
pub fn call_enclave<T>(input: CallEnclaveInput) -> Result<T, AbiError>
where
    T: CallEnclaveReturn,
{
    let mut out: *mut c_void = core::ptr::null_mut();
    let out_ptr: *mut *mut c_void = &mut out;
    let func_res = unsafe {
        BOOL(CallEnclave(
            input.func,
            input.in_params_ptr,
            WIN32_TRUE.0,
            out_ptr,
        ))
    };

    if !func_res.as_bool() {
        let last_err = unsafe { GetLastError() };
        return Err(AbiError::Win32Error(last_err));
    }

    T::from_edl_framework(out)
}

pub trait CallEnclaveReturn: Sized {
    fn from_edl_framework(ptr: *mut c_void) -> Result<Self, AbiError>;
}

impl CallEnclaveReturn for *mut c_void {
    fn from_edl_framework(ptr: *mut c_void) -> Result<Self, AbiError> {
        Ok(ptr)
    }
}
impl CallEnclaveReturn for () {
    fn from_edl_framework(ptr: *mut c_void) -> Result<Self, AbiError> {
        let hr = crate::helpers::pvoid_to_hresult(ptr);

        if hr == S_OK {
            return Ok(());
        }

        Err(AbiError::Hresult(hr))
    }
}
