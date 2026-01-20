// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Enclave implementation for the user-bound key sample.
//! Functionally equivalent to C++ SampleEnclave/UserBound/userbound_keys.cpp

#![allow(unused_imports)]
#![allow(non_snake_case)]

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use userboundkey_sample_enclave_gen::AbiError;
use userboundkey_sample_enclave_gen::implementation::trusted::Trusted;
use userboundkey_sample_enclave_gen::implementation::types::edl::WString;
use userboundkey_sample_enclave_gen::implementation::types::{DecryptResult, EncryptResult};
use userboundkey_sample_enclave_gen::stubs::untrusted::debug_print;

// Import SDK functions and types
use vbsenclave_sdk_enclave::userboundkey::{
    EnclaveSealingIdentityPolicy, SymmetricKeyHandle, TAG_SIZE, ZERO_NONCE, create_user_bound_key,
    decrypt, encrypt, keyCredentialCacheConfig, load_user_bound_key, reseal_user_bound_key,
};

/// Runtime policy: no dynamic debug allowed (matches C++ g_runtimePolicy = 0)
const RUNTIME_POLICY_NO_DEBUG: u32 = 0;

/// VTL1 function to create secure cache configuration.
/// This ensures VTL0 has no influence over cache configuration values.
/// Matches C++ CreateSecureKeyCredentialCacheConfig()
fn create_secure_cache_config() -> keyCredentialCacheConfig {
    keyCredentialCacheConfig {
        cacheOption: 0,           // NoCache - most secure option
        cacheTimeoutInSeconds: 0, // No timeout when not caching
        cacheUsageCount: 0,       // No usage count when not caching
    }
}

/// Global encryption key storage (matches C++ g_encryptionKey pattern)
/// In no_std enclave, we use a static mut with unsafe access
static mut ENCRYPTION_KEY: Option<SymmetricKeyHandle> = None;

#[allow(static_mut_refs)]
fn is_ubk_loaded() -> bool {
    unsafe { ENCRYPTION_KEY.is_some() }
}

#[allow(static_mut_refs)]
fn set_encryption_key(key: SymmetricKeyHandle) {
    unsafe {
        ENCRYPTION_KEY = Some(key);
    }
}

#[allow(static_mut_refs)]
fn get_encryption_key() -> Option<&'static SymmetricKeyHandle> {
    unsafe { ENCRYPTION_KEY.as_ref() }
}

/// Helper function to convert WString to String for SDK calls
fn wstring_to_string(ws: &WString) -> alloc::string::String {
    // WString stores UTF-16 in wchars field, convert to UTF-8 String
    alloc::string::String::from_utf16_lossy(&ws.wchars)
}

/// Helper function to ensure user-bound key is loaded.
/// Handles initial load attempt and optional reseal if needed.
/// Matches C++ EnsureUserBoundKeyLoaded()
fn ensure_user_bound_key_loaded(
    hello_key_name: &str,
    pin_message: &str,
    window_id: u64,
    secured_encryption_key_bytes: &[u8],
    needs_reseal: &mut bool,
    resealed_encryption_key_bytes: &mut Vec<u8>,
) -> Result<(), AbiError> {
    // Only load if not already loaded (matches C++ IsUBKLoaded check)
    if is_ubk_loaded() {
        return Ok(());
    }

    let secure_config = create_secure_cache_config();
    #[allow(unused_assignments)]
    let mut loaded_key_bytes: Vec<u8> = Vec::new();
    #[allow(unused_assignments)]
    let mut load_succeeded = false;

    // First attempt to load the user-bound key
    match load_user_bound_key(
        hello_key_name,
        &secure_config,
        pin_message,
        window_id,
        secured_encryption_key_bytes,
    ) {
        Ok((key_bytes, stale)) => {
            loaded_key_bytes = key_bytes;
            load_succeeded = true;

            // If stale, mark for reseal
            if stale {
                *needs_reseal = true;
                if let Ok(resealed) = reseal_user_bound_key(
                    &loaded_key_bytes,
                    EnclaveSealingIdentityPolicy::SealToExactCode,
                    RUNTIME_POLICY_NO_DEBUG,
                ) {
                    *resealed_encryption_key_bytes = resealed;
                }
            }
        }
        Err(e) => {
            // First load failed, attempt reseal and retry
            match reseal_user_bound_key(
                secured_encryption_key_bytes,
                EnclaveSealingIdentityPolicy::SealToExactCode,
                RUNTIME_POLICY_NO_DEBUG,
            ) {
                Ok(resealed_bytes) => {
                    *needs_reseal = true;
                    *resealed_encryption_key_bytes = resealed_bytes.clone();

                    // Retry loading with resealed bytes
                    match load_user_bound_key(
                        hello_key_name,
                        &secure_config,
                        pin_message,
                        window_id,
                        &resealed_bytes,
                    ) {
                        Ok((key_bytes, _)) => {
                            loaded_key_bytes = key_bytes;
                            load_succeeded = true;
                        }
                        Err(e2) => {
                            return Err(AbiError::Hresult(e2.to_hresult()));
                        }
                    }
                }
                Err(_) => {
                    return Err(AbiError::Hresult(e.to_hresult()));
                }
            }
        }
    }

    if !load_succeeded {
        return Err(AbiError::Hresult(-2147024809)); // E_INVALIDARG
    }

    // Create symmetric key from loaded raw key material
    // Matches C++: auto newEncryptionKey = veil::vtl1::crypto::create_symmetric_key(loadedKeyBytes);
    let symmetric_key = SymmetricKeyHandle::from_bytes(&loaded_key_bytes)
        .map_err(|e| AbiError::Hresult(e.to_hresult()))?;
    set_encryption_key(symmetric_key);

    Ok(())
}

/// Enclave implementation of the Trusted trait
pub struct EnclaveImpl;

impl Trusted for EnclaveImpl {
    /// Create a user-bound key.
    /// Matches C++ MyEnclaveCreateUserBoundKey()
    fn CreateUserBoundKey(
        helloKeyName: &WString,
        pinMessage: &WString,
        windowId: u64,
        keyCredentialCreationOption: u32,
    ) -> Result<Vec<u8>, AbiError> {
        let _ = debug_print(&String::from("CreateUserBoundKey: Starting"));

        let cache_config = create_secure_cache_config();
        let key_name = wstring_to_string(helloKeyName);
        let pin_msg = wstring_to_string(pinMessage);

        let _ = debug_print(&format!(
            "CreateUserBoundKey: key_name={}, windowId={}, option={}",
            key_name, windowId, keyCredentialCreationOption
        ));

        let _ = debug_print(&String::from(
            "CreateUserBoundKey: Calling SDK create_user_bound_key...",
        ));

        // Create user-bound key with enclave sealing
        // Matches C++: veil::vtl1::userboundkey::create_user_bound_key(...)
        let sealed_key = create_user_bound_key(
            &key_name,
            &cache_config,
            &pin_msg,
            windowId,
            EnclaveSealingIdentityPolicy::SealToExactCode,
            RUNTIME_POLICY_NO_DEBUG,
            keyCredentialCreationOption,
        )
        .map_err(|e| {
            let _ = debug_print(&format!("CreateUserBoundKey: SDK error: {:?}", e));
            AbiError::Hresult(e.to_hresult())
        })?;

        let _ = debug_print(&format!(
            "CreateUserBoundKey: Success! Got {} sealed bytes",
            sealed_key.len()
        ));

        // Return sealed key bytes - do NOT create symmetric key here
        // Matches C++ comment: "Do NOT try to create a symmetric key here"
        Ok(sealed_key)
    }

    /// Load user-bound key and encrypt data.
    /// Matches C++ MyEnclaveLoadUserBoundKeyAndEncryptData()
    fn LoadUserBoundKeyAndEncryptData(
        helloKeyName: &WString,
        pinMessage: &WString,
        windowId: u64,
        securedEncryptionKeyBytes: &Vec<u8>,
        inputData: &WString,
    ) -> Result<EncryptResult, AbiError> {
        let key_name = wstring_to_string(helloKeyName);
        let pin_msg = wstring_to_string(pinMessage);
        let mut needs_reseal = false;
        let mut resealed_bytes = Vec::new();

        // Ensure key is loaded (handles reseal if needed)
        ensure_user_bound_key_loaded(
            &key_name,
            &pin_msg,
            windowId,
            securedEncryptionKeyBytes,
            &mut needs_reseal,
            &mut resealed_bytes,
        )?;

        // Get the key and encrypt
        let key = get_encryption_key().ok_or(AbiError::Hresult(-2147024809))?;

        // Convert input to bytes (wchar_t / UTF-16 LE data like C++)
        // Matches C++: veil::vtl1::as_data_span(inputData.c_str())
        let input_bytes: Vec<u8> = inputData
            .wchars
            .iter()
            .flat_map(|c| c.to_le_bytes())
            .collect();

        // Encrypt using AES-GCM with zero nonce
        // Matches C++: veil::vtl1::crypto::encrypt(keyHandle, ..., veil::vtl1::crypto::zero_nonce)
        let (encrypted, tag) = encrypt(key, &input_bytes, &ZERO_NONCE)
            .map_err(|e| AbiError::Hresult(e.to_hresult()))?;

        // Combine tag and encrypted data into single output
        // Format: [tag_size (4 bytes)][tag_data][encrypted_data]
        // Matches C++ format exactly
        let tag_size = tag.len() as u32;
        let mut combined = Vec::with_capacity(4 + tag.len() + encrypted.len());
        combined.extend_from_slice(&tag_size.to_le_bytes());
        combined.extend_from_slice(&tag);
        combined.extend(encrypted);

        Ok(EncryptResult {
            combinedOutputData: combined,
            needsReseal: needs_reseal,
            resealedEncryptionKeyBytes: resealed_bytes,
        })
    }

    /// Load user-bound key and decrypt data.
    /// Matches C++ MyEnclaveLoadUserBoundKeyAndDecryptData()
    fn LoadUserBoundKeyAndDecryptData(
        helloKeyName: &WString,
        pinMessage: &WString,
        windowId: u64,
        securedEncryptionKeyBytes: &Vec<u8>,
        combinedInputData: &Vec<u8>,
    ) -> Result<DecryptResult, AbiError> {
        let key_name = wstring_to_string(helloKeyName);
        let pin_msg = wstring_to_string(pinMessage);
        let mut needs_reseal = false;
        let mut resealed_bytes = Vec::new();

        // Parse combined input: [tag_size (4 bytes)][tag_data][encrypted_data]
        // Matches C++ parsing logic
        if combinedInputData.len() < 4 {
            return Err(AbiError::Hresult(-2147024809)); // E_INVALIDARG
        }

        // Read tag size from first 4 bytes
        let tag_size = u32::from_le_bytes([
            combinedInputData[0],
            combinedInputData[1],
            combinedInputData[2],
            combinedInputData[3],
        ]) as usize;

        // Validate tag size
        if tag_size == 0 || tag_size > combinedInputData.len() - 4 {
            return Err(AbiError::Hresult(-2147024809)); // E_INVALIDARG
        }

        // Extract tag and encrypted data
        let tag = &combinedInputData[4..4 + tag_size];
        let encrypted = &combinedInputData[4 + tag_size..];

        // Ensure key is loaded
        ensure_user_bound_key_loaded(
            &key_name,
            &pin_msg,
            windowId,
            securedEncryptionKeyBytes,
            &mut needs_reseal,
            &mut resealed_bytes,
        )?;

        // Get the key and decrypt
        let key = get_encryption_key().ok_or(AbiError::Hresult(-2147024809))?;

        // Convert tag slice to fixed-size array
        let mut tag_array = [0u8; TAG_SIZE];
        if tag.len() != TAG_SIZE {
            return Err(AbiError::Hresult(-2147024809)); // E_INVALIDARG
        }
        tag_array.copy_from_slice(tag);

        // Decrypt using AES-GCM with zero nonce
        // Matches C++: veil::vtl1::crypto::decrypt(keyHandle, ..., veil::vtl1::crypto::zero_nonce, tag)
        let decrypted_bytes = decrypt(key, encrypted, &ZERO_NONCE, &tag_array)
            .map_err(|e| AbiError::Hresult(e.to_hresult()))?;

        // Convert decrypted bytes to WString (UTF-16 LE)
        // Matches C++: veil::vtl1::to_wstring(decryptedBytes)
        let utf16: Vec<u16> = decrypted_bytes
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();

        // Create WString from UTF-16 data
        let decrypted_string = WString { wchars: utf16 };

        Ok(DecryptResult {
            decryptedData: decrypted_string,
            needsReseal: needs_reseal,
            resealedEncryptionKeyBytes: resealed_bytes,
        })
    }
}
