// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Manual BCrypt bindings for types not included in the generated bindings.

/// Version for BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
pub const BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION: u32 = 1;

/// Authenticated cipher mode info structure for AES-GCM
///
/// This structure is used with BCryptEncrypt and BCryptDecrypt when using
/// authenticated encryption modes like AES-GCM.
///
/// See: https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_authenticated_cipher_mode_info
#[repr(C)]
#[derive(Clone, Default)]
pub struct BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
    pub cbSize: u32,
    pub dwInfoVersion: u32,
    pub pbNonce: *mut u8,
    pub cbNonce: u32,
    pub pbAuthData: *mut u8,
    pub cbAuthData: u32,
    pub pbTag: *mut u8,
    pub cbTag: u32,
    pub pbMacContext: *mut u8,
    pub cbMacContext: u32,
    pub cbAAD: u32,
    pub cbData: u64,
    pub dwFlags: u32,
}

impl BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
    /// Create a new initialized cipher mode info structure
    pub fn new() -> Self {
        Self {
            cbSize: core::mem::size_of::<Self>() as u32,
            dwInfoVersion: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION,
            ..Default::default()
        }
    }

    /// Create a new cipher mode info for encryption (tag will be written)
    pub fn for_encrypt(nonce: &mut [u8], tag: &mut [u8]) -> Self {
        Self {
            cbSize: core::mem::size_of::<Self>() as u32,
            dwInfoVersion: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION,
            pbNonce: nonce.as_mut_ptr(),
            cbNonce: nonce.len() as u32,
            pbTag: tag.as_mut_ptr(),
            cbTag: tag.len() as u32,
            ..Default::default()
        }
    }

    /// Create a new cipher mode info for decryption (tag is input)
    pub fn for_decrypt(nonce: &[u8], tag: &[u8]) -> Self {
        Self {
            cbSize: core::mem::size_of::<Self>() as u32,
            dwInfoVersion: BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_VERSION,
            pbNonce: nonce.as_ptr() as *mut u8,
            cbNonce: nonce.len() as u32,
            pbTag: tag.as_ptr() as *mut u8,
            cbTag: tag.len() as u32,
            ..Default::default()
        }
    }
}
