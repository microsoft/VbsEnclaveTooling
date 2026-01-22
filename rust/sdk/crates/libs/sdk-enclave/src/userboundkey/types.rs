// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Type definitions for user-bound key operations

use userboundkey_enclave_gen::AbiError;
use windows_enclave::vertdll::RtlNtStatusToDosError;

/// Error type for user-bound key operations
#[derive(Debug)]
pub enum UserBoundKeyError {
    /// HRESULT error from Windows API
    Hresult(i32),
    /// NTSTATUS error from BCrypt/NT APIs
    NtStatus(i32),
    /// ABI layer error
    AbiError(AbiError),
    /// Memory allocation failed
    AllocationFailed,
    /// Invalid data format
    InvalidData(&'static str),
    /// Security policy violation
    SecurityViolation(&'static str),
    /// The sealing key is stale and data needs to be resealed
    StaleKey,
    /// Feature not implemented
    NotImplemented(&'static str),
}

impl From<AbiError> for UserBoundKeyError {
    fn from(err: AbiError) -> Self {
        UserBoundKeyError::AbiError(err)
    }
}

/// Converts a Win32 error code to an HRESULT.
/// Equivalent to the HRESULT_FROM_WIN32 macro.
#[inline]
fn hresult_from_win32(error: u32) -> i32 {
    if error == 0 {
        0 // S_OK
    } else {
        // FACILITY_WIN32 = 7, so (7 << 16) | 0x80000000 = 0x80070000
        ((error & 0x0000FFFF) | 0x80070000) as i32
    }
}

impl UserBoundKeyError {
    /// Convert the error to an HRESULT code
    pub fn to_hresult(&self) -> i32 {
        match self {
            UserBoundKeyError::Hresult(hr) => *hr,
            // NTSTATUS to HRESULT: Convert via RtlNtStatusToDosError then HRESULT_FROM_WIN32
            UserBoundKeyError::NtStatus(status) => {
                // SAFETY: RtlNtStatusToDosError is a pure function that converts NTSTATUS to Win32 error
                let win32_error = unsafe { RtlNtStatusToDosError(*status) };
                hresult_from_win32(win32_error)
            }
            UserBoundKeyError::AbiError(e) => e.to_hresult().0,
            UserBoundKeyError::AllocationFailed => -2147024882, // E_OUTOFMEMORY
            UserBoundKeyError::InvalidData(_) => -2147024809,   // E_INVALIDARG
            UserBoundKeyError::SecurityViolation(_) => -2147024891, // E_ACCESSDENIED
            UserBoundKeyError::StaleKey => 0x80090325_u32 as i32, // SEC_E_BAD_PKGID or similar
            UserBoundKeyError::NotImplemented(_) => -2147467263, // E_NOTIMPL
        }
    }

    /// Check if this error indicates the sealing key is stale
    pub fn is_stale_key(&self) -> bool {
        matches!(self, UserBoundKeyError::StaleKey)
    }
}
