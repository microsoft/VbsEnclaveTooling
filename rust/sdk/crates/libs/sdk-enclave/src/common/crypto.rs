//! Common cryptographic utilities for VBS Enclave SDK
//!
//! This module provides general-purpose cryptographic functionality that can be
//! used across different modules in the SDK, including:
//! - BCrypt API wrappers and RAII types
//! - Enclave sealing and unsealing
//! - Random number generation
//! - AES-GCM encryption and decryption
//! - Error checking helpers

extern crate alloc;

use alloc::vec::Vec;
use core::ffi::c_void;
use core::fmt;
use windows_enclave::bcrypt::*;
use windows_enclave::vertdll::*;

/// Cryptographic operation errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// HRESULT failure from Windows API
    Hresult(i32),
    /// NTSTATUS failure from BCrypt/NT API
    NtStatus(i32),
    /// Authentication tag mismatch during decryption
    AuthTagMismatch,
    /// Data is too short for the expected format
    DataTooShort,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::Hresult(hr) => write!(f, "HRESULT error: 0x{:08x}", hr),
            CryptoError::NtStatus(status) => write!(f, "NTSTATUS error: 0x{:08x}", status),
            CryptoError::AuthTagMismatch => write!(f, "Authentication tag mismatch"),
            CryptoError::DataTooShort => write!(f, "Data too short"),
        }
    }
}

impl core::error::Error for CryptoError {}

/// Sealing identity policy for enclave data sealing
#[derive(Debug, Clone, Copy)]
pub enum EnclaveSealingIdentityPolicy {
    /// Seal to enclave identity (SIGNER + PRODUCT_ID + VERSION)
    EnclaveIdentity = 1,
    /// Seal to signer only (allows version upgrades)
    SignerOnly = 2,
}

//
// Helper functions (public for use by other modules)
//

/// Check HRESULT and convert to error
pub fn check_hr(hr: i32) -> Result<(), CryptoError> {
    if hr < 0 {
        return Err(CryptoError::Hresult(hr));
    }
    Ok(())
}

/// Check NTSTATUS and convert to error
pub fn check_ntstatus(status: i32) -> Result<(), CryptoError> {
    if status < 0 {
        return Err(CryptoError::NtStatus(status));
    }
    Ok(())
}

//
// Random number generation
//

/// Generate cryptographically secure random bytes
///
/// Uses BCryptGenRandom with BCRYPT_USE_SYSTEM_PREFERRED_RNG flag.
/// This is safe to call from enclaves as it uses the enclave's entropy source.
pub fn generate_random(buffer: &mut [u8]) -> Result<(), CryptoError> {
    unsafe {
        let status = BCryptGenRandom(
            core::ptr::null_mut(), // Use system RNG
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        );
        check_ntstatus(status)?;
    }
    Ok(())
}

/// Generate random bytes of the specified length
pub fn generate_random_bytes(count: usize) -> Result<Vec<u8>, CryptoError> {
    let mut buffer = alloc::vec![0u8; count];
    generate_random(&mut buffer)?;
    Ok(buffer)
}

/// Generate a cryptographically secure random u64
pub fn generate_random_u64() -> Result<u64, CryptoError> {
    let mut buffer = [0u8; 8];
    generate_random(&mut buffer)?;
    Ok(u64::from_le_bytes(buffer))
}

/// Generate random bytes suitable for use as a symmetric key
pub fn generate_symmetric_key_bytes(key_size: usize) -> Result<Vec<u8>, CryptoError> {
    generate_random_bytes(key_size)
}

//
// Enclave sealing
//

/// Seal data using enclave sealing
///
/// Encrypts data such that it can only be decrypted by the same enclave
/// (or enclaves with compatible identity based on the sealing policy).
///
/// # Arguments
/// * `data` - The data to seal
/// * `sealing_policy` - Identity policy for sealing
/// * `runtime_policy` - Runtime policy flags (pass 0 for default)
///
/// # Returns
/// The sealed data blob
pub fn seal_data(
    data: &[u8],
    sealing_policy: EnclaveSealingIdentityPolicy,
    runtime_policy: u32,
) -> Result<Vec<u8>, CryptoError> {
    unsafe {
        // First call to get required size
        let mut sealed_size: u32 = 0;
        let hr = EnclaveSealData(
            data.as_ptr() as *const c_void,
            data.len() as u32,
            sealing_policy as i32,
            runtime_policy,
            core::ptr::null_mut(),
            0,
            &mut sealed_size,
        );
        check_hr(hr)?;

        // Allocate Vec and seal directly into it
        let mut sealed_buffer = alloc::vec![0u8; sealed_size as usize];

        let hr = EnclaveSealData(
            data.as_ptr() as *const c_void,
            data.len() as u32,
            sealing_policy as i32,
            runtime_policy,
            sealed_buffer.as_mut_ptr() as *mut c_void,
            sealed_size,
            &mut sealed_size,
        );
        check_hr(hr)?;

        Ok(sealed_buffer)
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
/// A tuple of (unsealed_data, unseal_flags). Check unseal_flags for stale key flags
/// to determine if the sealing key has changed and the data should be resealed.
pub fn unseal_data(sealed_data: &[u8]) -> Result<(Vec<u8>, u32), CryptoError> {
    unsafe {
        // First call to get required size
        let mut unsealed_size: u32 = 0;
        let hr = EnclaveUnsealData(
            sealed_data.as_ptr() as *const c_void,
            sealed_data.len() as u32,
            core::ptr::null_mut(),
            0,
            &mut unsealed_size,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        );
        check_hr(hr)?;

        // Allocate Vec and unseal directly into it
        let mut unsealed_buffer = alloc::vec![0u8; unsealed_size as usize];
        let mut unseal_flags: u32 = 0;

        let hr = EnclaveUnsealData(
            sealed_data.as_ptr() as *const c_void,
            sealed_data.len() as u32,
            unsealed_buffer.as_mut_ptr() as *mut c_void,
            unsealed_size,
            &mut unsealed_size,
            core::ptr::null_mut(),
            &mut unseal_flags,
        );
        check_hr(hr)?;

        Ok((unsealed_buffer, unseal_flags))
    }
}

//
// Nonce utilities
//

/// Create a nonce buffer from a numeric value
///
/// Creates a 12-byte nonce with the value placed at the end (little-endian).
pub fn make_nonce_from_number(nonce: u64, nonce_size: usize) -> Vec<u8> {
    let mut buffer = alloc::vec![0u8; nonce_size];
    if nonce_size >= 8 {
        // Place nonce value at the end of the buffer
        let nonce_bytes = nonce.to_le_bytes();
        buffer[nonce_size - 8..].copy_from_slice(&nonce_bytes);
    }
    buffer
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
    pub fn from_bytes(key_bytes: &[u8]) -> Result<Self, CryptoError> {
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
/// * `nonce` - Nonce (IV) bytes
/// * `tag_size` - Size of authentication tag in bytes
///
/// # Returns
/// A tuple of (ciphertext, tag)
pub fn encrypt(
    key: &SymmetricKeyHandle,
    plaintext: &[u8],
    nonce: &[u8],
    tag_size: usize,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let mut tag = alloc::vec![0u8; tag_size];
    let mut nonce_copy = nonce.to_vec();

    // AES-GCM: ciphertext length equals plaintext length
    let mut ciphertext = alloc::vec![0u8; plaintext.len()];
    let mut result_size: u32 = 0;

    let cipher_info = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO::for_encrypt(&mut nonce_copy, &mut tag);

    unsafe {
        let status = BCryptEncrypt(
            key.handle(),
            plaintext.as_ptr(),
            plaintext.len() as u32,
            &cipher_info as *const _ as *const c_void,
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
/// * `nonce` - Nonce (IV) bytes used during encryption
/// * `tag` - Authentication tag from encryption
///
/// # Returns
/// The decrypted plaintext
pub fn decrypt(
    key: &SymmetricKeyHandle,
    ciphertext: &[u8],
    nonce: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    // AES-GCM: plaintext length equals ciphertext length
    let mut plaintext = alloc::vec![0u8; ciphertext.len()];
    let mut result_size: u32 = 0;

    let cipher_info = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO::for_decrypt(nonce, tag);

    unsafe {
        let status = BCryptDecrypt(
            key.handle(),
            ciphertext.as_ptr(),
            ciphertext.len() as u32,
            &cipher_info as *const _ as *const c_void,
            core::ptr::null_mut(), // No IV buffer (using nonce in cipher_info)
            0,
            plaintext.as_mut_ptr(),
            plaintext.len() as u32,
            &mut result_size,
            0,
        );

        // STATUS_AUTH_TAG_MISMATCH = 0xC000A002
        if status == -1073700862i32 {
            return Err(CryptoError::AuthTagMismatch);
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
/// * `nonce` - Nonce (IV) bytes
/// * `tag_size` - Size of authentication tag in bytes
///
/// # Returns
/// Combined output: [ciphertext][tag]
pub fn encrypt_and_tag(
    key: &SymmetricKeyHandle,
    plaintext: &[u8],
    nonce: &[u8],
    tag_size: usize,
) -> Result<Vec<u8>, CryptoError> {
    let (ciphertext, tag) = encrypt(key, plaintext, nonce, tag_size)?;

    let mut combined = Vec::with_capacity(ciphertext.len() + tag_size);
    combined.extend_from_slice(&ciphertext);
    combined.extend_from_slice(&tag);

    Ok(combined)
}

/// Decrypt data that has the tag appended
///
/// # Arguments
/// * `key` - The symmetric key handle
/// * `combined` - Combined input: [ciphertext][tag]
/// * `nonce` - Nonce (IV) bytes used during encryption
/// * `tag_size` - Size of authentication tag in bytes
///
/// # Returns
/// The decrypted plaintext
pub fn decrypt_and_untag(
    key: &SymmetricKeyHandle,
    combined: &[u8],
    nonce: &[u8],
    tag_size: usize,
) -> Result<Vec<u8>, CryptoError> {
    if combined.len() < tag_size {
        return Err(CryptoError::DataTooShort);
    }

    let ciphertext_len = combined.len() - tag_size;
    let ciphertext = &combined[..ciphertext_len];
    let tag = &combined[ciphertext_len..];

    decrypt(key, ciphertext, nonce, tag)
}

/// Encrypt data with a zero nonce and append tag
///
/// Uses a zero nonce (all zeros). Only safe when each key is used once.
pub fn encrypt_and_tag_zero_nonce(
    key: &SymmetricKeyHandle,
    plaintext: &[u8],
    nonce_size: usize,
    tag_size: usize,
) -> Result<Vec<u8>, CryptoError> {
    let zero_nonce = alloc::vec![0u8; nonce_size];
    encrypt_and_tag(key, plaintext, &zero_nonce, tag_size)
}

/// Decrypt data with a zero nonce that has tag appended
///
/// Uses a zero nonce (all zeros).
pub fn decrypt_and_untag_zero_nonce(
    key: &SymmetricKeyHandle,
    combined: &[u8],
    nonce_size: usize,
    tag_size: usize,
) -> Result<Vec<u8>, CryptoError> {
    let zero_nonce = alloc::vec![0u8; nonce_size];
    decrypt_and_untag(key, combined, &zero_nonce, tag_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_make_nonce_from_number() {
        let nonce = make_nonce_from_number(0x0102030405060708, 12);
        assert_eq!(nonce[0..4], [0, 0, 0, 0]);
        assert_eq!(
            nonce[4..12],
            [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );
    }
}
