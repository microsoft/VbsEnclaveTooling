// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Type definitions for user-bound key operations

/// Error type for user-bound key operations
#[derive(Debug)]
pub enum UserBoundKeyError {
    /// HRESULT error from Windows API
    Hresult(i32),
    /// ABI layer error
    AbiError(userboundkey_enclave_gen::AbiError),
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

impl From<userboundkey_enclave_gen::AbiError> for UserBoundKeyError {
    fn from(err: userboundkey_enclave_gen::AbiError) -> Self {
        UserBoundKeyError::AbiError(err)
    }
}

impl UserBoundKeyError {
    /// Convert the error to an HRESULT code
    pub fn to_hresult(&self) -> i32 {
        match self {
            UserBoundKeyError::Hresult(hr) => *hr,
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
