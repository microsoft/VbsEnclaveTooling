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
