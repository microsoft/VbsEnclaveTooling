// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Cryptographic utilities for VTL1 enclave operations
//!
//! This module provides crypto primitives used by user-bound key operations,
//! including random number generation, enclave sealing, and AES-GCM encryption.

use alloc::vec::Vec;

use windows_enclave::bcrypt::{
    BCRYPT_AES_GCM_ALG_HANDLE, BCRYPT_KEY_HANDLE, BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptDecrypt,
    BCryptDestroyKey, BCryptEncrypt, BCryptGenRandom, BCryptGenerateSymmetricKey,
};
use windows_enclave::vertdll::{
    ENCLAVE_UNSEAL_FLAG_STALE_KEY, EnclaveSealData, EnclaveUnsealData, GetProcessHeap,
    HEAP_ZERO_MEMORY, HeapAlloc, HeapFree,
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

/// Zero nonce for AES-GCM (all zeros)
pub const ZERO_NONCE: [u8; NONCE_SIZE] = [0u8; NONCE_SIZE];

//
// BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO structure
// This is not in the generated bindings, so we define it manually.
// See: https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_authenticated_cipher_mode_info
//

/// Version for BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
const BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION: u32 = 1;

/// Authenticated cipher mode info structure for AES-GCM
#[repr(C)]
#[derive(Clone)]
pub struct BcryptAuthenticatedCipherModeInfo {
    pub cb_size: u32,
    pub dw_info_version: u32,
    pub pb_nonce: *mut u8,
    pub cb_nonce: u32,
    pub pb_auth_data: *mut u8,
    pub cb_auth_data: u32,
    pub pb_tag: *mut u8,
    pub cb_tag: u32,
    pub pb_mac_context: *mut u8,
    pub cb_mac_context: u32,
    pub cb_aad: u32,
    pub cb_data: u64,
    pub dw_flags: u32,
}

impl Default for BcryptAuthenticatedCipherModeInfo {
    fn default() -> Self {
        Self {
            cb_size: core::mem::size_of::<Self>() as u32,
            dw_info_version: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION,
            pb_nonce: core::ptr::null_mut(),
            cb_nonce: 0,
            pb_auth_data: core::ptr::null_mut(),
            cb_auth_data: 0,
            pb_tag: core::ptr::null_mut(),
            cb_tag: 0,
            pb_mac_context: core::ptr::null_mut(),
            cb_mac_context: 0,
            cb_aad: 0,
            cb_data: 0,
            dw_flags: 0,
        }
    }
}

impl BcryptAuthenticatedCipherModeInfo {
    /// Create a new cipher mode info for encryption (tag will be written)
    pub fn for_encrypt(nonce: &mut [u8], tag: &mut [u8]) -> Self {
        Self {
            cb_size: core::mem::size_of::<Self>() as u32,
            dw_info_version: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION,
            pb_nonce: nonce.as_mut_ptr(),
            cb_nonce: nonce.len() as u32,
            pb_auth_data: core::ptr::null_mut(),
            cb_auth_data: 0,
            pb_tag: tag.as_mut_ptr(),
            cb_tag: tag.len() as u32,
            pb_mac_context: core::ptr::null_mut(),
            cb_mac_context: 0,
            cb_aad: 0,
            cb_data: 0,
            dw_flags: 0,
        }
    }

    /// Create a new cipher mode info for decryption (tag is input)
    pub fn for_decrypt(nonce: &[u8], tag: &[u8]) -> Self {
        Self {
            cb_size: core::mem::size_of::<Self>() as u32,
            dw_info_version: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION,
            pb_nonce: nonce.as_ptr() as *mut u8,
            cb_nonce: nonce.len() as u32,
            pb_auth_data: core::ptr::null_mut(),
            cb_auth_data: 0,
            pb_tag: tag.as_ptr() as *mut u8,
            cb_tag: tag.len() as u32,
            pb_mac_context: core::ptr::null_mut(),
            cb_mac_context: 0,
            cb_aad: 0,
            cb_data: 0,
            dw_flags: 0,
        }
    }
}

//
// Symmetric Key Handle (RAII wrapper)
//

/// RAII wrapper for BCrypt symmetric key handle
pub struct SymmetricKeyHandle {
    handle: BCRYPT_KEY_HANDLE,
}

impl SymmetricKeyHandle {
    /// Create a symmetric key from raw key bytes using AES-GCM
    pub fn from_bytes(key_bytes: &[u8]) -> Result<Self, UserBoundKeyError> {
        let mut handle: BCRYPT_KEY_HANDLE = core::ptr::null_mut();

        unsafe {
            let status = BCryptGenerateSymmetricKey(
                BCRYPT_AES_GCM_ALG_HANDLE,
                &mut handle,
                core::ptr::null_mut(), // No key object buffer needed
                0,
                key_bytes.as_ptr(),
                key_bytes.len() as u32,
                0,
            );
            check_ntstatus(status)?;
        }

        Ok(Self { handle })
    }

    /// Get the raw handle for use with BCrypt functions
    pub fn handle(&self) -> BCRYPT_KEY_HANDLE {
        self.handle
    }
}

impl Drop for SymmetricKeyHandle {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                let _ = BCryptDestroyKey(self.handle);
            }
        }
    }
}

//
// AES-GCM Encryption / Decryption
//

/// Encrypt data using AES-GCM
///
/// # Arguments
/// * `key` - The symmetric key handle
/// * `plaintext` - Data to encrypt
/// * `nonce` - 12-byte nonce (IV)
///
/// # Returns
/// A tuple of (ciphertext, tag) where tag is 16 bytes
pub fn encrypt(
    key: &SymmetricKeyHandle,
    plaintext: &[u8],
    nonce: &[u8; NONCE_SIZE],
) -> Result<(Vec<u8>, [u8; TAG_SIZE]), UserBoundKeyError> {
    let mut tag = [0u8; TAG_SIZE];
    let mut nonce_copy = *nonce;

    // AES-GCM: ciphertext length equals plaintext length
    let mut ciphertext = alloc::vec![0u8; plaintext.len()];
    let mut result_size: u32 = 0;

    let cipher_info = BcryptAuthenticatedCipherModeInfo::for_encrypt(&mut nonce_copy, &mut tag);

    unsafe {
        let status = BCryptEncrypt(
            key.handle(),
            plaintext.as_ptr(),
            plaintext.len() as u32,
            &cipher_info as *const _ as *const core::ffi::c_void,
            core::ptr::null_mut(), // No IV buffer (using nonce in cipher_info)
            0,
            ciphertext.as_mut_ptr(),
            ciphertext.len() as u32,
            &mut result_size,
            0,
        );
        check_ntstatus(status)?;
    }

    Ok((ciphertext, tag))
}

/// Decrypt data using AES-GCM
///
/// # Arguments
/// * `key` - The symmetric key handle
/// * `ciphertext` - Data to decrypt
/// * `nonce` - 12-byte nonce (IV) used during encryption
/// * `tag` - 16-byte authentication tag from encryption
///
/// # Returns
/// The decrypted plaintext
pub fn decrypt(
    key: &SymmetricKeyHandle,
    ciphertext: &[u8],
    nonce: &[u8; NONCE_SIZE],
    tag: &[u8; TAG_SIZE],
) -> Result<Vec<u8>, UserBoundKeyError> {
    // AES-GCM: plaintext length equals ciphertext length
    let mut plaintext = alloc::vec![0u8; ciphertext.len()];
    let mut result_size: u32 = 0;

    let cipher_info = BcryptAuthenticatedCipherModeInfo::for_decrypt(nonce, tag);

    unsafe {
        let status = BCryptDecrypt(
            key.handle(),
            ciphertext.as_ptr(),
            ciphertext.len() as u32,
            &cipher_info as *const _ as *const core::ffi::c_void,
            core::ptr::null_mut(), // No IV buffer (using nonce in cipher_info)
            0,
            plaintext.as_mut_ptr(),
            plaintext.len() as u32,
            &mut result_size,
            0,
        );

        // STATUS_AUTH_TAG_MISMATCH = 0xC000A002
        if status == -1073700862i32 {
            return Err(UserBoundKeyError::InvalidData(
                "Authentication tag mismatch",
            ));
        }
        check_ntstatus(status)?;
    }

    Ok(plaintext)
}

/// Encrypt data and append the tag to the output
///
/// # Arguments
/// * `key` - The symmetric key handle
/// * `plaintext` - Data to encrypt
/// * `nonce` - 12-byte nonce (IV)
///
/// # Returns
/// Combined output: [ciphertext][tag:16 bytes]
pub fn encrypt_and_tag(
    key: &SymmetricKeyHandle,
    plaintext: &[u8],
    nonce: &[u8; NONCE_SIZE],
) -> Result<Vec<u8>, UserBoundKeyError> {
    let (ciphertext, tag) = encrypt(key, plaintext, nonce)?;

    let mut combined = Vec::with_capacity(ciphertext.len() + TAG_SIZE);
    combined.extend_from_slice(&ciphertext);
    combined.extend_from_slice(&tag);

    Ok(combined)
}

/// Encrypt data with zero nonce and append tag
///
/// Uses a zero nonce (all zeros). Only safe when each key is used once.
pub fn encrypt_and_tag_zero_nonce(
    key: &SymmetricKeyHandle,
    plaintext: &[u8],
) -> Result<Vec<u8>, UserBoundKeyError> {
    encrypt_and_tag(key, plaintext, &ZERO_NONCE)
}

/// Decrypt data that has the tag appended
///
/// # Arguments
/// * `key` - The symmetric key handle
/// * `combined` - Combined input: [ciphertext][tag:16 bytes]
/// * `nonce` - 12-byte nonce (IV) used during encryption
///
/// # Returns
/// The decrypted plaintext
pub fn decrypt_and_untag(
    key: &SymmetricKeyHandle,
    combined: &[u8],
    nonce: &[u8; NONCE_SIZE],
) -> Result<Vec<u8>, UserBoundKeyError> {
    if combined.len() < TAG_SIZE {
        return Err(UserBoundKeyError::InvalidData("Data too short for tag"));
    }

    let ciphertext_len = combined.len() - TAG_SIZE;
    let ciphertext = &combined[..ciphertext_len];
    let tag: [u8; TAG_SIZE] = combined[ciphertext_len..]
        .try_into()
        .map_err(|_| UserBoundKeyError::InvalidData("Invalid tag length"))?;

    decrypt(key, ciphertext, nonce, &tag)
}

/// Decrypt data with zero nonce that has tag appended
///
/// Uses a zero nonce (all zeros).
pub fn decrypt_and_untag_zero_nonce(
    key: &SymmetricKeyHandle,
    combined: &[u8],
) -> Result<Vec<u8>, UserBoundKeyError> {
    decrypt_and_untag(key, combined, &ZERO_NONCE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_make_nonce_from_number() {
        let nonce = make_nonce_from_number(0x0102030405060708);
        assert_eq!(nonce[0..4], [0, 0, 0, 0]);
        assert_eq!(
            nonce[4..12],
            [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );
    }

    #[test]
    fn test_is_stale_key() {
        assert!(!is_stale_key(0));
        assert!(is_stale_key(ENCLAVE_UNSEAL_FLAG_STALE_KEY));
        assert!(is_stale_key(ENCLAVE_UNSEAL_FLAG_STALE_KEY | 0x10));
    }
}
