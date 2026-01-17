// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Cryptographic utilities for VTL1 enclave operations
//!
//! This module provides crypto primitives used by user-bound key operations,
//! including random number generation and enclave sealing.

use alloc::vec::Vec;

use windows_enclave::bcrypt::{BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG};
use windows_enclave::vertdll::{
    EnclaveSealData, EnclaveUnsealData, GetProcessHeap, HEAP_ZERO_MEMORY, HeapAlloc, HeapFree,
    ENCLAVE_UNSEAL_FLAG_STALE_KEY,
};

use super::types::UserBoundKeyError;

//
// Constants
//

/// Size of symmetric key in bytes (AES-256-GCM)
pub const SYMMETRIC_KEY_SIZE_BYTES: usize = 32;

/// Size of DH key in bits (ECDH P-384)
#[allow(dead_code)]
pub const DH_KEY_SIZE_BITS: usize = 384;

/// Size of signature key in bits (ECDSA P-384)
#[allow(dead_code)]
pub const SIGNATURE_KEY_SIZE_BITS: usize = 384;

/// Size of nonce in bytes
#[allow(dead_code)]
pub const NONCE_SIZE: usize = 12;

/// Size of authentication tag in bytes
#[allow(dead_code)]
pub const TAG_SIZE: usize = 16;

//
// Types
//

/// Fixed-size symmetric key bytes
pub type SymmetricKeyBytes = [u8; SYMMETRIC_KEY_SIZE_BYTES];

/// Enclave sealing identity policy
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnclaveSealingIdentityPolicy {
    /// Seal to the exact enclave image
    SealToExactCode = 1,
    /// Seal to the enclave signer
    SealToSigner = 2,
}

//
// RAII Helpers
//

/// RAII wrapper for heap-allocated memory
pub struct HeapBuffer {
    ptr: *mut core::ffi::c_void,
    size: usize,
}

impl HeapBuffer {
    /// Allocate a new heap buffer of the specified size
    pub fn new(size: usize) -> Option<Self> {
        unsafe {
            let heap = GetProcessHeap();
            let ptr = HeapAlloc(heap, HEAP_ZERO_MEMORY, size);
            if ptr.is_null() {
                None
            } else {
                Some(Self { ptr, size })
            }
        }
    }

    /// Get a const pointer to the buffer
    #[allow(dead_code)]
    pub fn as_ptr(&self) -> *const core::ffi::c_void {
        self.ptr
    }

    /// Get a mutable pointer to the buffer
    pub fn as_mut_ptr(&mut self) -> *mut core::ffi::c_void {
        self.ptr
    }

    /// Get the buffer contents as a slice
    pub fn as_slice(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.ptr as *const u8, self.size) }
    }

    /// Copy the buffer contents to a Vec
    pub fn to_vec(&self) -> Vec<u8> {
        self.as_slice().to_vec()
    }
}

impl Drop for HeapBuffer {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                let heap = GetProcessHeap();
                HeapFree(heap, 0, self.ptr);
            }
        }
    }
}

//
// Helper Functions
//

/// Convert HRESULT to Result
pub fn check_hr(hr: i32) -> Result<(), UserBoundKeyError> {
    if hr >= 0 {
        Ok(())
    } else {
        Err(UserBoundKeyError::Hresult(hr))
    }
}

//
// Random Number Generation
//

/// Convert NTSTATUS to Result
fn check_ntstatus(status: i32) -> Result<(), UserBoundKeyError> {
    if status >= 0 {
        Ok(())
    } else {
        // Convert NTSTATUS to HRESULT-like error
        // NTSTATUS errors have the high bit set; HRESULT uses 0x8xxxxxxx format
        Err(UserBoundKeyError::Hresult(status))
    }
}

/// Generate random bytes using BCryptGenRandom
///
/// Uses the system preferred RNG to generate cryptographically secure random bytes.
pub fn generate_random<const N: usize>() -> Result<[u8; N], UserBoundKeyError> {
    let mut buffer = [0u8; N];
    generate_random_bytes(&mut buffer)?;
    Ok(buffer)
}

/// Generate random bytes into a mutable slice
#[allow(dead_code)]
pub fn generate_random_bytes(buffer: &mut [u8]) -> Result<(), UserBoundKeyError> {
    unsafe {
        // BCryptGenRandom with BCRYPT_USE_SYSTEM_PREFERRED_RNG uses the system RNG
        // and doesn't require an algorithm handle (pass null)
        let status = BCryptGenRandom(
            core::ptr::null_mut(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        );
        check_ntstatus(status)
    }
}

/// Generate a symmetric key (32 bytes of random data)
pub fn generate_symmetric_key_bytes() -> Result<SymmetricKeyBytes, UserBoundKeyError> {
    generate_random::<SYMMETRIC_KEY_SIZE_BYTES>()
}

//
// Enclave Sealing
//

/// Seal data using enclave sealing
///
/// Encrypts and binds data to the enclave identity according to the specified policy.
///
/// # Arguments
/// * `data` - The plaintext data to seal
/// * `sealing_policy` - The identity policy for sealing
/// * `runtime_policy` - Runtime policy flags
///
/// # Returns
/// The sealed (encrypted) data blob
pub fn seal_data(
    data: &[u8],
    sealing_policy: EnclaveSealingIdentityPolicy,
    runtime_policy: u32,
) -> Result<Vec<u8>, UserBoundKeyError> {
    unsafe {
        // First call to get required size
        let mut sealed_size: u32 = 0;
        let hr = EnclaveSealData(
            data.as_ptr() as *const core::ffi::c_void,
            data.len() as u32,
            sealing_policy as i32,
            runtime_policy,
            core::ptr::null_mut(),
            0,
            &mut sealed_size,
        );
        check_hr(hr)?;

        // Allocate buffer and seal
        let mut sealed_buffer =
            HeapBuffer::new(sealed_size as usize).ok_or(UserBoundKeyError::AllocationFailed)?;

        let hr = EnclaveSealData(
            data.as_ptr() as *const core::ffi::c_void,
            data.len() as u32,
            sealing_policy as i32,
            runtime_policy,
            sealed_buffer.as_mut_ptr(),
            sealed_size,
            &mut sealed_size,
        );
        check_hr(hr)?;

        Ok(sealed_buffer.to_vec())
    }
}

/// Unseal data using enclave sealing
///
/// Decrypts data that was previously sealed to this enclave.
///
/// # Arguments
/// * `sealed_data` - The sealed data blob
///
/// # Returns
/// A tuple of (unsealed_data, unseal_flags). Check unseal_flags for ENCLAVE_UNSEAL_FLAG_STALE_KEY
/// to determine if the sealing key has changed and the data should be resealed.
pub fn unseal_data(sealed_data: &[u8]) -> Result<(Vec<u8>, u32), UserBoundKeyError> {
    unsafe {
        // First call to get required size
        let mut unsealed_size: u32 = 0;
        let hr = EnclaveUnsealData(
            sealed_data.as_ptr() as *const core::ffi::c_void,
            sealed_data.len() as u32,
            core::ptr::null_mut(),
            0,
            &mut unsealed_size,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        );
        check_hr(hr)?;

        // Allocate buffer and unseal
        let mut unsealed_buffer =
            HeapBuffer::new(unsealed_size as usize).ok_or(UserBoundKeyError::AllocationFailed)?;
        let mut unseal_flags: u32 = 0;

        let hr = EnclaveUnsealData(
            sealed_data.as_ptr() as *const core::ffi::c_void,
            sealed_data.len() as u32,
            unsealed_buffer.as_mut_ptr(),
            unsealed_size,
            &mut unsealed_size,
            core::ptr::null_mut(),
            &mut unseal_flags,
        );
        check_hr(hr)?;

        Ok((unsealed_buffer.to_vec(), unseal_flags))
    }
}

/// Check if unseal flags indicate a stale key
///
/// When the sealing key has rotated, unsealing still succeeds but sets this flag
/// to indicate the data should be resealed with the new key.
#[inline]
pub fn is_stale_key(unseal_flags: u32) -> bool {
    (unseal_flags & ENCLAVE_UNSEAL_FLAG_STALE_KEY) != 0
}

//
// Nonce utilities
//

/// Create a nonce buffer from a numeric value
///
/// Creates a 12-byte nonce with the value placed at the end (big-endian position).
#[allow(dead_code)]
pub fn make_nonce_from_number(nonce: u64) -> [u8; NONCE_SIZE] {
    let mut buffer = [0u8; NONCE_SIZE];
    // Place nonce value at the end of the buffer
    let nonce_bytes = nonce.to_le_bytes();
    buffer[NONCE_SIZE - 8..].copy_from_slice(&nonce_bytes);
    buffer
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_make_nonce_from_number() {
        let nonce = make_nonce_from_number(0x0102030405060708);
        assert_eq!(nonce[0..4], [0, 0, 0, 0]);
        assert_eq!(nonce[4..12], [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
    }

    #[test]
    fn test_is_stale_key() {
        assert!(!is_stale_key(0));
        assert!(is_stale_key(ENCLAVE_UNSEAL_FLAG_STALE_KEY));
        assert!(is_stale_key(ENCLAVE_UNSEAL_FLAG_STALE_KEY | 0x10));
    }
}
