// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! VTL0 User-Bound Key Implementation
//!
//! Implements EDL untrusted callbacks for user-bound key operations.
//! This module provides VTL0/host-side Windows Hello integration with VBS enclave support.

/// Debug print macro that only prints in debug builds.
/// Similar to C++ `#ifdef _VEIL_INTERNAL_DEBUG` pattern.
macro_rules! debug_print {
    ($($arg:tt)*) => {
        #[cfg(debug_assertions)]
        {
            println!($($arg)*);
        }
    };
}

use sdk_host_gen::AbiError;
pub use sdk_host_gen::SdkHost;
pub use sdk_host_gen::implementation::types::{
    attestationReportAndSessionInfo, credentialAndSessionInfo, keyCredentialCacheConfig,
};

use std::sync::{Arc, Mutex};

use windows::{
    Security::Cryptography::CryptographicBuffer,
    Storage::Streams::IBuffer,
    Win32::{
        Foundation::{CloseHandle, E_FAIL, E_INVALIDARG, HANDLE, HLOCAL, LocalFree},
        Security::Authorization::ConvertSidToStringSidW,
        Security::{GetTokenInformation, PSID, TOKEN_QUERY, TOKEN_USER, TokenUser},
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    },
    core::HSTRING,
};
use windows_core::{Interface, PWSTR};

use userboundkey_kcm::{
    AttestationChallengeHandler, ChallengeResponseKind, IBuffer as KcmIBuffer,
    IKeyCredentialCacheConfigurationFactory, KeyCredential, KeyCredentialCacheConfiguration,
    KeyCredentialCacheOption, KeyCredentialCreationOption, KeyCredentialManager,
    KeyCredentialStatus, TimeSpan, WindowId,
};
use widestring::{U16Str, U16String};
/// RAII wrapper for session handle that calls back to VTL1 on cleanup
struct UniqueSessionHandle {
    handle: usize,
    enclave_ptr: usize,
}

impl UniqueSessionHandle {
    fn new() -> Self {
        Self {
            handle: 0,
            enclave_ptr: 0,
        }
    }

    #[allow(dead_code)]
    fn get(&self) -> usize {
        self.handle
    }

    fn release(&mut self) -> usize {
        let result = self.handle;
        self.handle = 0;
        self.enclave_ptr = 0;
        result
    }

    fn set(&mut self, handle: usize, enclave_ptr: usize) {
        self.reset();
        self.handle = handle;
        self.enclave_ptr = enclave_ptr;
    }

    fn reset(&mut self) {
        if self.handle != 0 && self.enclave_ptr != 0 {
            // Call back to VTL1 to close session
            let enclave_interface = SdkHost::new(self.enclave_ptr as *mut core::ffi::c_void);
            let _ = enclave_interface.userboundkey_close_session(self.handle as u64);
        }
        self.handle = 0;
        self.enclave_ptr = 0;
    }
}

impl Drop for UniqueSessionHandle {
    fn drop(&mut self) {
        self.reset();
    }
}

/// Convert a Windows IBuffer to a Vec<u8>
fn buffer_to_vec(buffer: &IBuffer) -> windows_core::Result<Vec<u8>> {
    let mut byte_array = windows::core::Array::<u8>::new();
    CryptographicBuffer::CopyToByteArray(buffer, &mut byte_array)?;
    Ok(byte_array.to_vec())
}

/// Convert Vec<u8> to a Windows IBuffer
fn vec_to_buffer(data: &[u8]) -> windows_core::Result<IBuffer> {
    CryptographicBuffer::CreateFromByteArray(data)
}

/// Convert a KcmIBuffer (from userboundkey-kcm) to Vec<u8>
fn kcm_buffer_to_vec(buffer: &KcmIBuffer) -> windows_core::Result<Vec<u8>> {
    // Cast KcmIBuffer to windows IBuffer
    let windows_buffer: IBuffer = buffer.cast()?;
    buffer_to_vec(&windows_buffer)
}

/// Convert Vec<u8> to a KcmIBuffer
fn vec_to_kcm_buffer(data: &[u8]) -> windows_core::Result<KcmIBuffer> {
    let windows_buffer = vec_to_buffer(data)?;
    windows_buffer.cast()
}

/// Get the algorithm name string from the ECDH algorithm handle
fn get_algorithm(ecdh_algorithm: u64) -> Result<HSTRING, AbiError> {
    // BCrypt algorithm pseudo-handle values from Windows SDK bcrypt.h
    const BCRYPT_ECDH_P384_ALG_HANDLE: u64 = 0x000002b1;
    const BCRYPT_ECDH_P256_ALG_HANDLE: u64 = 0x000002a1;

    if ecdh_algorithm == BCRYPT_ECDH_P384_ALG_HANDLE {
        Ok(HSTRING::from("ECDH_P384"))
    } else if ecdh_algorithm == BCRYPT_ECDH_P256_ALG_HANDLE {
        Ok(HSTRING::from("ECDH_P256"))
    } else {
        Err(AbiError::Hresult(E_INVALIDARG.0))
    }
}

/// Convert keyCredentialCacheConfig to the WinRT KeyCredentialCacheConfiguration
fn convert_cache_config(
    cache_config: &keyCredentialCacheConfig,
) -> windows_core::Result<KeyCredentialCacheConfiguration> {
    let cache_option = match cache_config.cacheOption {
        0 => KeyCredentialCacheOption::NoCache,
        1 => KeyCredentialCacheOption::CacheWhenUnlocked,
        _ => KeyCredentialCacheOption::NoCache,
    };

    // Convert timeout from seconds to TimeSpan (100-nanosecond units)
    let timeout = TimeSpan {
        Duration: (cache_config.cacheTimeoutInSeconds as i64) * 10_000_000,
    };

    // Use activation factory to create instance
    let factory = windows_core::factory::<
        KeyCredentialCacheConfiguration,
        IKeyCredentialCacheConfigurationFactory,
    >()?;
    factory.CreateInstance(cache_option, timeout, cache_config.cacheUsageCount)
}

/// Create an attestation challenge callback that calls into VTL1
fn create_challenge_callback(
    session_info: Arc<Mutex<UniqueSessionHandle>>,
    enclave_ptr: usize,
) -> AttestationChallengeHandler {
    AttestationChallengeHandler::new(move |challenge: windows_core::Ref<KcmIBuffer>| {
        debug_print!("[SDK-Host] Challenge callback invoked!");

        // Get the IBuffer reference using ok() which returns Result<&T>
        let challenge_buffer: &KcmIBuffer = challenge.ok()?;
        // Convert KcmIBuffer to Vec<u8>
        let challenge_vec = kcm_buffer_to_vec(challenge_buffer)?;

        debug_print!(
            "[SDK-Host] Challenge size: {} bytes, calling VTL1 for attestation report...",
            challenge_vec.len()
        );

        // Call into VTL1 to get attestation report
        let enclave_interface = SdkHost::new(enclave_ptr as *mut core::ffi::c_void);
        let attestation_result = enclave_interface
            .userboundkey_get_attestation_report(&challenge_vec)
            .map_err(|_e| {
                debug_print!("[SDK-Host] VTL1 attestation call failed: {:?}", _e);
                windows_core::Error::from(E_FAIL)
            })?;

        debug_print!(
            "[SDK-Host] Got attestation report: {} bytes",
            attestation_result.report.len()
        );

        // Store session handle
        {
            let mut session = match session_info.lock() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    debug_print!(
                        "[SDK-Host] Warning: session_info mutex was poisoned: {:?}",
                        poisoned
                    );
                    // Recover the guard from the poisoned mutex - the data may still be usable
                    poisoned.into_inner()
                }
            };
            session.set(attestation_result.sessionInfo as usize, enclave_ptr);
        }

        // Convert report to KcmIBuffer
        vec_to_kcm_buffer(&attestation_result.report)
    })
}

/// Convert a PSID to a wide string representation (Vec<u16>)
fn sid_to_wide_string(sid: PSID) -> Result<Vec<u16>, AbiError> {
    unsafe {
        let mut string_sid = PWSTR::null();
        ConvertSidToStringSidW(sid, &mut string_sid).map_err(|_| AbiError::Hresult(E_FAIL.0))?;

        // Convert PWSTR to Vec<u16>
        let len = (0..).take_while(|&i| *string_sid.0.add(i) != 0).count();
        let slice = std::slice::from_raw_parts(string_sid.0, len);
        let result = slice.to_vec();

        // Free the memory allocated by ConvertSidToStringSidW
        let _ = LocalFree(Some(HLOCAL(string_sid.0 as *mut _)));

        Ok(result)
    }
}

/// Helper to convert WString to HSTRING
fn wstring_to_hstring(ws: &U16Str) -> HSTRING {
    HSTRING::from_wide(ws.as_slice())
}

/// Establish a session for creating a new Windows Hello key.
#[allow(non_snake_case)]
#[allow(unused_variables)]
pub fn userboundkey_establish_session_for_create(
    enclave: u64,
    keyName: &U16Str,
    ecdhProtocol: u64,
    message: &U16Str,
    windowId: u64,
    cacheConfig: &keyCredentialCacheConfig,
    keyCredentialCreationOption: u32,
) -> Result<credentialAndSessionInfo, AbiError> {
    debug_print!("[SDK-Host] userboundkey_establish_session_for_create called");
    debug_print!(
        "[SDK-Host]   windowId={}, option={}",
        windowId,
        keyCredentialCreationOption
    );

    let algorithm = get_algorithm(ecdhProtocol)?;
    debug_print!("[SDK-Host]   algorithm resolved");

    let cache_configuration =
        convert_cache_config(cacheConfig).map_err(|e| AbiError::Hresult(e.code().0))?;
    debug_print!("[SDK-Host]   cache config created");

    let session_info = Arc::new(Mutex::new(UniqueSessionHandle::new()));
    let enclave_ptr = enclave as usize;

    // Try to delete existing key first (ignore errors)
    let key_name_hstring = wstring_to_hstring(keyName);
    debug_print!("[SDK-Host]   Deleting existing key (if any)...");
    if let Ok(delete_op) = KeyCredentialManager::DeleteAsync(&key_name_hstring) {
        let _ = delete_op.join();
    }
    debug_print!("[SDK-Host]   Delete complete");

    // Create the credential with VBS attestation
    let message_hstring = wstring_to_hstring(message);
    let win_id = WindowId { Value: windowId };
    let creation_option = KeyCredentialCreationOption(keyCredentialCreationOption as i32);

    let callback = create_challenge_callback(session_info.clone(), enclave_ptr);

    debug_print!("[SDK-Host]   Calling KeyCredentialManager::RequestCreateAsync2...");

    let credential_result = KeyCredentialManager::RequestCreateAsync2(
        &key_name_hstring,
        creation_option,
        &algorithm,
        &message_hstring,
        &cache_configuration,
        win_id,
        ChallengeResponseKind::VirtualizationBasedSecurityEnclave,
        &callback,
    )
    .map_err(|_e| {
        debug_print!("[SDK-Host]   RequestCreateAsync2 failed to start: {:?}", _e);
        AbiError::Hresult(_e.code().0)
    })?;

    debug_print!("[SDK-Host]   RequestCreateAsync2 started, waiting for completion (join)...");

    let credential_result = credential_result.join().map_err(|_e| {
        debug_print!("[SDK-Host]   RequestCreateAsync2.join() failed: {:?}", _e);
        AbiError::Hresult(_e.code().0)
    })?;

    debug_print!("[SDK-Host]   RequestCreateAsync2 completed!");

    // Check if operation was successful
    let status = credential_result
        .Status()
        .map_err(|e| AbiError::Hresult(e.code().0))?;
    if status != KeyCredentialStatus::Success {
        return Err(AbiError::Hresult(status.0));
    }

    // Get credential and convert to raw pointer
    let credential = credential_result
        .Credential()
        .map_err(|e| AbiError::Hresult(e.code().0))?;
    let credential_ptr = windows_core::Interface::as_raw(&credential) as u64;

    // Transfer session ownership
    let session_handle = {
        let mut session = match session_info.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                debug_print!("[SDK-Host] Warning: session_info mutex was poisoned");
                poisoned.into_inner()
            }
        };
        session.release() as u64
    };

    // Add reference to credential since we're transferring ownership
    // We need to prevent the credential from being released
    std::mem::forget(credential);

    Ok(credentialAndSessionInfo {
        credential: credential_ptr,
        sessionInfo: session_handle,
    })
}

/// Establish a session for loading an existing Windows Hello key.
#[allow(non_snake_case)]
#[allow(unused_variables)]
pub fn userboundkey_establish_session_for_load(
    enclave: u64,
    keyName: &U16Str,
    message: &U16Str,
    windowId: u64,
) -> Result<credentialAndSessionInfo, AbiError> {
    let _ = (message, windowId); // Mark as intentionally unused
    let session_info = Arc::new(Mutex::new(UniqueSessionHandle::new()));
    let enclave_ptr = enclave as usize;

    let key_name_hstring = wstring_to_hstring(keyName);
    let callback = create_challenge_callback(session_info.clone(), enclave_ptr);

    let credential_result = KeyCredentialManager::OpenAsync2(
        &key_name_hstring,
        ChallengeResponseKind::VirtualizationBasedSecurityEnclave,
        &callback,
    )
    .map_err(|e| AbiError::Hresult(e.code().0))?
    .join()
    .map_err(|e| AbiError::Hresult(e.code().0))?;

    // Check if operation was successful
    let status = credential_result
        .Status()
        .map_err(|e| AbiError::Hresult(e.code().0))?;
    if status != KeyCredentialStatus::Success {
        return Err(AbiError::Hresult(status.0));
    }

    // Get credential and convert to raw pointer
    let credential = credential_result
        .Credential()
        .map_err(|e| AbiError::Hresult(e.code().0))?;
    let credential_ptr = windows_core::Interface::as_raw(&credential) as u64;

    // Transfer session ownership
    let session_handle = {
        let mut session = match session_info.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                debug_print!("[SDK-Host] Warning: session_info mutex was poisoned");
                poisoned.into_inner()
            }
        };
        session.release() as u64
    };

    // Prevent credential from being released (transfer ownership)
    std::mem::forget(credential);

    Ok(credentialAndSessionInfo {
        credential: credential_ptr,
        sessionInfo: session_handle,
    })
}

/// Get authorization context from a credential.
#[allow(non_snake_case)]
#[allow(unused_variables)]
#[allow(clippy::ptr_arg)] // Signature must match EDL-generated trait
pub fn userboundkey_get_authorization_context_from_credential(
    credential: u64,
    encryptedRequest: &[u8],
    message: &U16Str,
    windowId: u64,
) -> Result<Vec<u8>, AbiError> {
    // Reconstruct KeyCredential from raw pointer
    // We use from_raw and then manually AddRef since the caller owns the credential
    let key_credential: KeyCredential = unsafe {
        let raw_ptr = credential as *mut core::ffi::c_void;
        if raw_ptr.is_null() {
            return Err(AbiError::Hresult(E_INVALIDARG.0));
        }
        // Clone increases ref count - the original is still owned by caller
        let temp = KeyCredential::from_raw(raw_ptr);
        let cloned = temp.clone();
        // Forget temp to not decrement refcount
        core::mem::forget(temp);
        cloned
    };

    // Convert encrypted request to IBuffer
    let encrypted_buffer =
        vec_to_kcm_buffer(encryptedRequest).map_err(|e| AbiError::Hresult(e.code().0))?;

    // Call RetrieveAuthorizationContext on the credential
    let auth_context = key_credential
        .RetrieveAuthorizationContext(&encrypted_buffer)
        .map_err(|e| AbiError::Hresult(e.code().0))?;

    kcm_buffer_to_vec(&auth_context).map_err(|e| AbiError::Hresult(e.code().0))
}

/// Get shared secret from a credential.
#[allow(non_snake_case)]
#[allow(unused_variables)]
#[allow(clippy::ptr_arg)] // Signature must match EDL-generated trait
pub fn userboundkey_get_secret_from_credential(
    credential: u64,
    encryptedRequest: &[u8],
    message: &U16Str,
    windowId: u64,
) -> Result<Vec<u8>, AbiError> {
    // Reconstruct KeyCredential from raw pointer
    // We use from_raw and then manually AddRef since the caller owns the credential
    let key_credential: KeyCredential = unsafe {
        let raw_ptr = credential as *mut core::ffi::c_void;
        if raw_ptr.is_null() {
            return Err(AbiError::Hresult(E_INVALIDARG.0));
        }
        // Clone increases ref count - the original is still owned by caller
        let temp = KeyCredential::from_raw(raw_ptr);
        let cloned = temp.clone();
        // Forget temp to not decrement refcount
        core::mem::forget(temp);
        cloned
    };

    // Convert encrypted request to IBuffer
    let encrypted_buffer =
        vec_to_kcm_buffer(encryptedRequest).map_err(|e| AbiError::Hresult(e.code().0))?;

    let win_id = WindowId { Value: windowId };
    let message_hstring = wstring_to_hstring(message);

    // Call RequestDeriveSharedSecretAsync on the credential
    let operation_result = key_credential
        .RequestDeriveSharedSecretAsync(win_id, &message_hstring, &encrypted_buffer)
        .map_err(|e| AbiError::Hresult(e.code().0))?
        .join()
        .map_err(|e| AbiError::Hresult(e.code().0))?;

    let result_buffer = operation_result
        .Result()
        .map_err(|e| AbiError::Hresult(e.code().0))?;

    kcm_buffer_to_vec(&result_buffer).map_err(|e| AbiError::Hresult(e.code().0))
}

/// Format a key name with the current user's SID.
#[allow(non_snake_case)]
pub fn userboundkey_format_key_name(keyName: &U16Str) -> Result<U16String, AbiError> {
    unsafe {
        let mut process_token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut process_token)
            .map_err(|_| AbiError::Hresult(E_FAIL.0))?;

        // Get token user info size
        let mut return_length: u32 = 0;
        let _ = GetTokenInformation(process_token, TokenUser, None, 0, &mut return_length);

        // Allocate buffer and get token user info
        let mut buffer = vec![0u8; return_length as usize];
        GetTokenInformation(
            process_token,
            TokenUser,
            Some(buffer.as_mut_ptr() as *mut _),
            return_length,
            &mut return_length,
        )
        .map_err(|_| AbiError::Hresult(E_FAIL.0))?;

        let _ = CloseHandle(process_token);

        let token_user = &*(buffer.as_ptr() as *const TOKEN_USER);
        let user_sid = token_user.User.Sid;

        // Convert SID to wide string
        let sid_wide = sid_to_wide_string(user_sid)?;

        // Build formatted key: {SID}//{SID}//{keyName}
        let slash_slash = widestring::u16str!("//");
        let mut result =
            Vec::with_capacity(sid_wide.len() + 2 + sid_wide.len() + 2 + keyName.len());
        result.extend_from_slice(&sid_wide);
        result.extend_from_slice(slash_slash.as_slice());
        result.extend_from_slice(&sid_wide);
        result.extend_from_slice(slash_slash.as_slice());
        result.extend_from_slice(keyName.as_slice());

        Ok(U16String::from_vec(result))
    }
}

/// Delete a credential handle.
#[allow(non_snake_case)]
pub fn userboundkey_delete_credential(credential: u64) -> Result<(), AbiError> {
    if credential == 0 {
        return Ok(());
    }

    // Take ownership of the credential and let it drop
    unsafe {
        let raw_ptr = credential as *mut core::ffi::c_void;
        let _ = KeyCredential::from_raw(raw_ptr);
        // Credential will be released when dropped
    }

    Ok(())
}
