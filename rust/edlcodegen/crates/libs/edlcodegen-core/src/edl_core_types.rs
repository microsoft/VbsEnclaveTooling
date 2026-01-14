// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use core::ffi::c_void;

/// Represents a buffer and its size used for enclave data exchange.
#[repr(C)]
#[derive(Default)]
pub struct EnclaveParameters {
    pub buffer: *mut core::ffi::c_void,

    pub buffer_size: usize,
}

/// Function call context exchanged across the enclave trust boundary.
#[repr(C)]
#[derive(Default)]
pub struct EnclaveFunctionContext {
    pub forwarded_parameters: EnclaveParameters,

    pub returned_parameters: EnclaveParameters,
}

/// Represents enclave <--> host call errors in a structured form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbiError {
    Win32Error(u32),
    Hresult(i32),
}

impl AbiError {
    pub fn to_hresult(&self) -> HRESULT {
        match *self {
            AbiError::Win32Error(code) => HRESULT::from_win32(code),
            AbiError::Hresult(hr) => HRESULT(hr),
        }
    }
}

pub struct EnclaveHandle(pub *mut c_void);

// The following subset of types/consts were taken from the windows_sys::Win32::Foundation.
// We need to make sure that this crate can be usable in both the host and the enclave
// and not accidentally bring in things that are not usable inside an enclave.
pub type EnclaveRoutine = isize;
pub type AbiFuncPtr = unsafe extern "system" fn(*mut c_void) -> *mut c_void;
pub const HEAP_ZERO_MEMORY: u32 = 8u32;
pub const S_OK: i32 = 0x0_u32 as _;
pub const E_FAIL: i32 = 0x80004005_u32 as _;
pub const E_INVALIDARG: i32 = 0x80070057_u32 as _;
pub static WIN32_FALSE: BOOL = BOOL(0);
pub static WIN32_TRUE: BOOL = BOOL(1);

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
