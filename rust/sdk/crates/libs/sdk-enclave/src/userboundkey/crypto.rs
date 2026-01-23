// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! User-bound key specific cryptographic constants and utilities.
//!
//! This module provides UBK-specific constants and convenience wrappers over
//! `common::crypto` that use UBK-specific sizes and error types.

use crate::common::crypto;
use crate::userboundkey::types::UserBoundKeyError;
use alloc::{string::ToString, vec::Vec};

// Re-export from common
pub use crypto::{
    EnclaveSealingIdentityPolicy, SymmetricKeyHandle, check_hr, generate_symmetric_key_bytes,
    seal_data, unseal_data,
};

//
// UBK-specific constants
//

/// Size of symmetric keys in bytes (AES-256)
pub const SYMMETRIC_KEY_SIZE_BYTES: usize = 32;

/// Size of Diffie-Hellman keys in bits
#[allow(dead_code)]
pub const DH_KEY_SIZE_BITS: u32 = 384;

/// Size of nonce for AES-GCM in bytes
pub const NONCE_SIZE: usize = 12;

/// Size of authentication tag for AES-GCM in bytes
pub const TAG_SIZE: usize = 16;

/// Flag indicating that the unsealing key is stale and data should be resealed
pub const ENCLAVE_UNSEAL_FLAG_STALE_KEY: u32 = 0x00000001;

/// Zero nonce for AES-GCM (all zeros)
pub const ZERO_NONCE: [u8; NONCE_SIZE] = [0u8; NONCE_SIZE];

//
// UBK-specific functions
//

/// Check if unseal flags indicate a stale key
#[inline]
pub fn is_stale_key(unseal_flags: u32) -> bool {
    (unseal_flags & ENCLAVE_UNSEAL_FLAG_STALE_KEY) != 0
}

/// Encrypt data using AES-GCM with UBK constants.
///
/// This is a convenience wrapper over `common::crypto::encrypt` that uses
/// UBK-specific tag size and returns `UserBoundKeyError`.
pub fn encrypt(
    key: &SymmetricKeyHandle,
    plaintext: &[u8],
    nonce: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), UserBoundKeyError> {
    crypto::encrypt(key, plaintext, nonce, TAG_SIZE)
        .map_err(|e| UserBoundKeyError::CryptoError(e.to_string()))
}

/// Decrypt data using AES-GCM.
///
/// This is a convenience wrapper over `common::crypto::decrypt` that returns
/// `UserBoundKeyError`.
pub fn decrypt(
    key: &SymmetricKeyHandle,
    ciphertext: &[u8],
    nonce: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, UserBoundKeyError> {
    crypto::decrypt(key, ciphertext, nonce, tag).map_err(|e| {
        let error_str = e.to_string();
        if error_str.contains("Authentication tag mismatch") {
            UserBoundKeyError::InvalidData("Authentication tag mismatch")
        } else {
            UserBoundKeyError::CryptoError(error_str)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_stale_key() {
        assert!(!is_stale_key(0));
        assert!(is_stale_key(ENCLAVE_UNSEAL_FLAG_STALE_KEY));
        assert!(is_stale_key(ENCLAVE_UNSEAL_FLAG_STALE_KEY | 0x10));
    }
}
