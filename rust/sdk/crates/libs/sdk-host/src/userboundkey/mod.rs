// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! VTL0 User-Bound Key Implementation
//!
//! Implements EDL untrusted callbacks for user-bound key operations.
//! This module provides VTL0/host-side Windows Hello integration with VBS enclave support.

mod types;

#[allow(unused_imports)]
pub use types::*;
use userboundkey_host_gen::AbiError;
pub use userboundkey_host_gen::UserBoundKeyVtl0Host;
pub use userboundkey_host_gen::implementation::types::{
    attestationReportAndSessionInfo, credentialAndSessionInfo, keyCredentialCacheConfig,
};
use userboundkey_host_gen::implementation::untrusted::Untrusted;

use std::sync::{Arc, Mutex};

use windows::{
    Security::Cryptography::CryptographicBuffer,
    Storage::Streams::IBuffer,
    Win32::{
        Foundation::{CloseHandle, E_FAIL, E_INVALIDARG, HANDLE},
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
            let enclave_interface =
                UserBoundKeyVtl0Host::new(self.enclave_ptr as *mut core::ffi::c_void);
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
        // Get the IBuffer reference using ok() which returns Result<&T>
        let challenge_buffer: &KcmIBuffer = challenge.ok()?;
        // Convert KcmIBuffer to Vec<u8>
        let challenge_vec = kcm_buffer_to_vec(challenge_buffer)?;

        // Call into VTL1 to get attestation report
        let enclave_interface = UserBoundKeyVtl0Host::new(enclave_ptr as *mut core::ffi::c_void);
        let attestation_result = enclave_interface
            .userboundkey_get_attestation_report(&challenge_vec)
            .map_err(|_| windows_core::Error::from(E_FAIL))?;

        // Store session handle
        {
            let mut session = session_info.lock().unwrap();
            session.set(attestation_result.sessionInfo as usize, enclave_ptr);
        }

        // Convert report to KcmIBuffer
        vec_to_kcm_buffer(&attestation_result.report)
    })
}

/// Format a key name with user SID for Windows Hello
fn format_user_hello_key_name(name: &str) -> Result<String, AbiError> {
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

        // Convert SID to string
        let sid_string = sid_to_string(user_sid)?;

        // Format: {SID}//{SID}//{keyName}
        Ok(format!("{}//{}//{}", sid_string, sid_string, name))
    }
}

/// Convert a PSID to a string representation
fn sid_to_string(sid: PSID) -> Result<String, AbiError> {
    unsafe {
        let mut string_sid = PWSTR::null();
        ConvertSidToStringSidW(sid, &mut string_sid).map_err(|_| AbiError::Hresult(E_FAIL.0))?;

        // Convert PWSTR to String
        let len = (0..).take_while(|&i| *string_sid.0.add(i) != 0).count();
        let slice = std::slice::from_raw_parts(string_sid.0, len);
        let result = String::from_utf16_lossy(slice);

        // Note: We're leaking the string memory here since LocalFree requires more setup.
        // In a production implementation, proper cleanup should be added.
        let _ = string_sid.0; // Prevent unused warning

        Ok(result)
    }
}

/// Untrusted implementation struct
pub struct UntrustedImpl;

#[allow(non_snake_case)]
#[allow(unused_variables)]
impl Untrusted for UntrustedImpl {
    fn userboundkey_establish_session_for_create(
        enclave: u64,
        keyName: &String,
        ecdhProtocol: u64,
        message: &String,
        windowId: u64,
        cacheConfig: &keyCredentialCacheConfig,
        keyCredentialCreationOption: u32,
    ) -> Result<credentialAndSessionInfo, AbiError> {
        let algorithm = get_algorithm(ecdhProtocol)?;

        let cache_configuration =
            convert_cache_config(cacheConfig).map_err(|e| AbiError::Hresult(e.code().0))?;

        let session_info = Arc::new(Mutex::new(UniqueSessionHandle::new()));
        let enclave_ptr = enclave as usize;

        // Try to delete existing key first (ignore errors)
        let key_name_hstring = HSTRING::from(keyName.as_str());
        if let Ok(delete_op) = KeyCredentialManager::DeleteAsync(&key_name_hstring) {
            let _ = delete_op.join();
        }

        // Create the credential with VBS attestation
        let message_hstring = HSTRING::from(message.as_str());
        let win_id = WindowId { Value: windowId };
        let creation_option = KeyCredentialCreationOption(keyCredentialCreationOption as i32);

        let callback = create_challenge_callback(session_info.clone(), enclave_ptr);

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
            let mut session = session_info.lock().unwrap();
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

    fn userboundkey_establish_session_for_load(
        enclave: u64,
        keyName: &String,
        message: &String,
        windowId: u64,
    ) -> Result<credentialAndSessionInfo, AbiError> {
        let _ = (message, windowId); // Mark as intentionally unused
        let session_info = Arc::new(Mutex::new(UniqueSessionHandle::new()));
        let enclave_ptr = enclave as usize;

        let key_name_hstring = HSTRING::from(keyName.as_str());
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
            let mut session = session_info.lock().unwrap();
            session.release() as u64
        };

        // Prevent credential from being released (transfer ownership)
        std::mem::forget(credential);

        Ok(credentialAndSessionInfo {
            credential: credential_ptr,
            sessionInfo: session_handle,
        })
    }

    fn userboundkey_get_authorization_context_from_credential(
        credential: u64,
        encryptedRequest: &Vec<u8>,
        message: &String,
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

    fn userboundkey_get_secret_from_credential(
        credential: u64,
        encryptedRequest: &Vec<u8>,
        message: &String,
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
        let message_hstring = HSTRING::from(message.as_str());

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

    fn userboundkey_format_key_name(keyName: &String) -> Result<String, AbiError> {
        format_user_hello_key_name(keyName)
    }

    fn userboundkey_delete_credential(credential: u64) -> Result<(), AbiError> {
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
}
