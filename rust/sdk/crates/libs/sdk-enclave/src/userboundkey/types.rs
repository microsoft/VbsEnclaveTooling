// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Type definitions for user-bound key operations

use crate::common::{CryptoError, EnclaveUtilsError, ntstatus_to_hresult};
use alloc::string::String;
use vbsenclave_sdk_enclave_gen::AbiError;

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
    /// General cryptographic error
    CryptoError(String),
}

impl From<AbiError> for UserBoundKeyError {
    fn from(err: AbiError) -> Self {
        UserBoundKeyError::AbiError(err)
    }
}

impl From<EnclaveUtilsError> for UserBoundKeyError {
    fn from(err: EnclaveUtilsError) -> Self {
        match err {
            EnclaveUtilsError::Hresult(hr) => UserBoundKeyError::Hresult(hr),
        }
    }
}

impl From<CryptoError> for UserBoundKeyError {
    fn from(err: CryptoError) -> Self {
        match err {
            CryptoError::Hresult(hr) => UserBoundKeyError::Hresult(hr),
            CryptoError::NtStatus(status) => UserBoundKeyError::NtStatus(status),
            CryptoError::AuthTagMismatch => {
                UserBoundKeyError::CryptoError(String::from("Authentication tag mismatch"))
            }
            CryptoError::DataTooShort => {
                UserBoundKeyError::CryptoError(String::from("Data too short for tag"))
            }
        }
    }
}

impl UserBoundKeyError {
    /// Convert the error to an HRESULT code
    pub fn to_hresult(&self) -> i32 {
        match self {
            UserBoundKeyError::Hresult(hr) => *hr,
            UserBoundKeyError::NtStatus(status) => ntstatus_to_hresult(*status),
            UserBoundKeyError::AbiError(e) => e.to_hresult().0,
            UserBoundKeyError::AllocationFailed => -2147024882, // E_OUTOFMEMORY
            UserBoundKeyError::InvalidData(_) => -2147024809,   // E_INVALIDARG
            UserBoundKeyError::SecurityViolation(_) => -2147024891, // E_ACCESSDENIED
            UserBoundKeyError::StaleKey => 0x80090325_u32 as i32, // SEC_E_BAD_PKGID or similar
            UserBoundKeyError::NotImplemented(_) => -2147467263, // E_NOTIMPL
            UserBoundKeyError::CryptoError(_) => -2147467259,   // E_FAIL
        }
    }

    /// Check if this error indicates the sealing key is stale
    pub fn is_stale_key(&self) -> bool {
        matches!(self, UserBoundKeyError::StaleKey)
    }
}
