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
