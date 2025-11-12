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
    pub fn to_hresult(&self) -> windows_result::HRESULT {
        match *self {
            AbiError::Win32Error(code) => windows_result::HRESULT::from_win32(code),
            AbiError::Hresult(hr) => windows_result::HRESULT(hr),
        }
    }
}

pub struct EnclaveHandle(pub *mut c_void);
