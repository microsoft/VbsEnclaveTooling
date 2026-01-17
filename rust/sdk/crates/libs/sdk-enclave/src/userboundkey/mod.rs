// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! VTL1 User-Bound Key Implementation
//!
//! Implements enclave-side user-bound key operations using VBS enclave sealing
//! and the veinterop.dll APIs for KCM (Key Credential Manager) interactions.

mod crypto;
mod types;
mod utils;

pub use crypto::{
    EnclaveSealingIdentityPolicy, SYMMETRIC_KEY_SIZE_BYTES,
};
pub use types::*;

use alloc::vec::Vec;

use userboundkey_enclave_gen::implementation::trusted::Trusted;
use userboundkey_enclave_gen::implementation::types::{
    attestationReportAndSessionInfo, keyCredentialCacheConfig,
};
use userboundkey_enclave_gen::stubs::untrusted;

use windows_enclave::veinterop::{
    CloseUserBoundKeyAuthContext, CloseUserBoundKeySession,
    CreateUserBoundKeyRequestForDeriveSharedSecret,
    CreateUserBoundKeyRequestForRetrieveAuthorizationContext, GetUserBoundKeyAuthContext,
    InitializeUserBoundKeySession, ProtectUserBoundKey, USER_BOUND_KEY_AUTH_CONTEXT_HANDLE,
    USER_BOUND_KEY_AUTH_CONTEXT_PROPERTY, USER_BOUND_KEY_AUTH_CONTEXT_PROPERTY_NAME,
    USER_BOUND_KEY_SESSION_HANDLE, UnprotectUserBoundKey, ValidateUserBoundKeyAuthContext,
};
use windows_enclave::vertdll::{GetProcessHeap, HeapFree};

use crypto::{check_hr, generate_symmetric_key_bytes, is_stale_key, seal_data, unseal_data};
use utils::get_enclave_base_address_u64;

// BCrypt algorithm pseudo-handle value from Windows SDK bcrypt.h.
// BCRYPT_ECDH_P384_ALG_HANDLE = ((BCRYPT_ALG_HANDLE) 0x000002b1)
// Stored as u64 for EDL interface compatibility.
const BCRYPT_ECDH_P384_ALG_HANDLE_U64: u64 = 0x000002b1;

/// RAII wrapper for session handle
struct UniqueSessionHandle(USER_BOUND_KEY_SESSION_HANDLE);

impl UniqueSessionHandle {
    fn new(handle: USER_BOUND_KEY_SESSION_HANDLE) -> Self {
        Self(handle)
    }

    fn get(&self) -> USER_BOUND_KEY_SESSION_HANDLE {
        self.0
    }

    #[allow(dead_code)]
    fn release(&mut self) -> USER_BOUND_KEY_SESSION_HANDLE {
        let handle = self.0;
        self.0 = core::ptr::null_mut();
        handle
    }
}

impl Drop for UniqueSessionHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _ = CloseUserBoundKeySession(self.0);
            }
        }
    }
}

/// RAII wrapper for auth context handle
struct UniqueAuthContextHandle(USER_BOUND_KEY_AUTH_CONTEXT_HANDLE);

impl UniqueAuthContextHandle {
    fn get(&self) -> USER_BOUND_KEY_AUTH_CONTEXT_HANDLE {
        self.0
    }
}

impl Drop for UniqueAuthContextHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _ = CloseUserBoundKeyAuthContext(self.0);
            }
        }
    }
}

/// RAII wrapper for credential (calls VTL0 to delete)
struct UniqueCredential(u64);

impl UniqueCredential {
    fn new(credential: u64) -> Self {
        Self(credential)
    }

    fn get(&self) -> u64 {
        self.0
    }

    #[allow(dead_code)]
    fn release(&mut self) -> u64 {
        let credential = self.0;
        self.0 = 0;
        credential
    }
}

impl Drop for UniqueCredential {
    fn drop(&mut self) {
        if self.0 != 0 {
            let _ = untrusted::userboundkey_delete_credential(self.0);
        }
    }
}

/// Get ephemeral public key bytes from bound key structure
///
/// The bound key structure format:
/// - [4 bytes] enclave public key blob size
/// - [N bytes] enclave public key blob (ephemeral public key)
fn get_ephemeral_public_key_bytes_from_bound_key(
    bound_key_bytes: &[u8],
) -> Result<Vec<u8>, UserBoundKeyError> {
    if bound_key_bytes.len() < 4 {
        return Err(UserBoundKeyError::InvalidData("Bound key too small"));
    }

    let public_key_size = u32::from_le_bytes([
        bound_key_bytes[0],
        bound_key_bytes[1],
        bound_key_bytes[2],
        bound_key_bytes[3],
    ]) as usize;

    let remaining = bound_key_bytes.len() - 4;
    if remaining < public_key_size || public_key_size == 0 {
        return Err(UserBoundKeyError::InvalidData("Invalid public key size"));
    }

    Ok(bound_key_bytes[4..4 + public_key_size].to_vec())
}

/// Validate that formatted key name ends with expected suffix
fn validate_formatted_key_name(
    formatted_key_name: &str,
    original_key_name: &str,
) -> Result<(), UserBoundKeyError> {
    let expected_suffix = alloc::format!("//{}", original_key_name);
    if !formatted_key_name.ends_with(&expected_suffix) {
        return Err(UserBoundKeyError::SecurityViolation(
            "Formatted key name does not match expected pattern",
        ));
    }
    Ok(())
}

/// Create a new user-bound key
///
/// This function:
/// 1. Generates a symmetric key
/// 2. Creates a Windows Hello credential with VBS attestation
/// 3. Protects the key using the KCM auth context
/// 4. Seals the protected key to the enclave
///
/// # Arguments
/// * `key_name` - Name for the Windows Hello credential
/// * `cache_config` - Cache configuration for the credential
/// * `message` - Message to display during Windows Hello prompt
/// * `window_id` - Window ID for the prompt
/// * `sealing_policy` - Enclave sealing identity policy
/// * `runtime_policy` - Runtime policy flags
/// * `key_credential_creation_option` - Credential creation options
///
/// # Returns
/// Sealed key material that can be stored and later loaded
pub fn create_user_bound_key(
    key_name: &str,
    cache_config: &keyCredentialCacheConfig,
    message: &str,
    window_id: u64,
    sealing_policy: EnclaveSealingIdentityPolicy,
    runtime_policy: u32,
    key_credential_creation_option: u32,
) -> Result<Vec<u8>, UserBoundKeyError> {
    // Generate symmetric key
    let user_key_bytes = generate_symmetric_key_bytes()?;

    create_user_bound_key_with_custom_key(
        key_name,
        cache_config,
        message,
        window_id,
        sealing_policy,
        runtime_policy,
        key_credential_creation_option,
        &user_key_bytes,
    )
}

/// Create a user-bound key with custom key bytes
pub fn create_user_bound_key_with_custom_key(
    key_name: &str,
    cache_config: &keyCredentialCacheConfig,
    message: &str,
    window_id: u64,
    sealing_policy: EnclaveSealingIdentityPolicy,
    runtime_policy: u32,
    key_credential_creation_option: u32,
    custom_key_bytes: &[u8],
) -> Result<Vec<u8>, UserBoundKeyError> {
    // Format the key name (calls VTL0)
    let formatted_key_name = untrusted::userboundkey_format_key_name(&key_name.into())
        .map_err(|e| UserBoundKeyError::AbiError(e))?;

    // Security validation
    validate_formatted_key_name(&formatted_key_name, key_name)?;

    // Get enclave base address
    let enclave_ptr = get_enclave_base_address_u64()?;

    // Establish session (calls VTL0 which triggers Windows Hello)
    let credential_and_session = untrusted::userboundkey_establish_session_for_create(
        enclave_ptr,
        &key_name.into(),
        BCRYPT_ECDH_P384_ALG_HANDLE_U64,
        &message.into(),
        window_id,
        cache_config,
        key_credential_creation_option,
    )
    .map_err(|e| UserBoundKeyError::AbiError(e))?;

    // RAII wrappers for cleanup
    let credential = UniqueCredential::new(credential_and_session.credential);
    let session_handle = UniqueSessionHandle::new(
        credential_and_session.sessionInfo as USER_BOUND_KEY_SESSION_HANDLE,
    );

    // Create encrypted KCM request for RetrieveAuthorizationContext
    let mut encrypted_request_ptr: *mut core::ffi::c_void = core::ptr::null_mut();
    let mut encrypted_request_size: u32 = 0;
    let mut local_nonce: u64 = 0;

    // Convert formatted key name to wide string
    let formatted_key_name_wide: Vec<u16> = formatted_key_name
        .encode_utf16()
        .chain(core::iter::once(0))
        .collect();

    unsafe {
        let hr = CreateUserBoundKeyRequestForRetrieveAuthorizationContext(
            session_handle.get(),
            formatted_key_name_wide.as_ptr(),
            &mut local_nonce,
            &mut encrypted_request_ptr,
            &mut encrypted_request_size,
        );
        check_hr(hr)?;
    }

    // Convert to Vec
    let encrypted_request = unsafe {
        core::slice::from_raw_parts(
            encrypted_request_ptr as *const u8,
            encrypted_request_size as usize,
        )
        .to_vec()
    };

    // Free the allocated memory
    unsafe {
        let heap = GetProcessHeap();
        HeapFree(heap, 0, encrypted_request_ptr);
    }

    // Get authorization context from credential (calls VTL0)
    let auth_context_blob = untrusted::userboundkey_get_authorization_context_from_credential(
        credential.get(),
        &encrypted_request,
        &message.into(),
        window_id,
    )
    .map_err(|e| UserBoundKeyError::AbiError(e))?;

    // Get auth context handle
    let mut auth_context_handle: USER_BOUND_KEY_AUTH_CONTEXT_HANDLE = core::ptr::null_mut();
    unsafe {
        let hr = GetUserBoundKeyAuthContext(
            session_handle.get(),
            auth_context_blob.as_ptr() as *const core::ffi::c_void,
            auth_context_blob.len() as u32,
            local_nonce,
            &mut auth_context_handle,
        );
        check_hr(hr)?;
    }
    let auth_context = UniqueAuthContextHandle(auth_context_handle);

    // Validate auth context
    let prop = USER_BOUND_KEY_AUTH_CONTEXT_PROPERTY {
        name: USER_BOUND_KEY_AUTH_CONTEXT_PROPERTY_NAME::UserBoundKeyAuthContextPropertyCacheConfig,
        size: core::mem::size_of::<keyCredentialCacheConfig>() as u32,
        value: cache_config as *const _ as *mut core::ffi::c_void,
    };

    unsafe {
        let hr = ValidateUserBoundKeyAuthContext(
            formatted_key_name_wide.as_ptr(),
            auth_context.get(),
            1,
            &prop,
        );
        check_hr(hr)?;
    }

    // Protect the user key
    let mut bound_key_ptr: *mut core::ffi::c_void = core::ptr::null_mut();
    let mut bound_key_size: u32 = 0;

    unsafe {
        let hr = ProtectUserBoundKey(
            auth_context.get(),
            custom_key_bytes.as_ptr() as *const core::ffi::c_void,
            custom_key_bytes.len() as u32,
            &mut bound_key_ptr,
            &mut bound_key_size,
        );
        check_hr(hr)?;
    }

    // Convert bound key to Vec
    let bound_key_bytes = unsafe {
        core::slice::from_raw_parts(bound_key_ptr as *const u8, bound_key_size as usize).to_vec()
    };

    // Free the allocated memory
    unsafe {
        let heap = GetProcessHeap();
        HeapFree(heap, 0, bound_key_ptr);
    }

    // Seal the bound key
    let sealed_key = seal_data(&bound_key_bytes, sealing_policy, runtime_policy)?;

    Ok(sealed_key)
}

/// Load a previously created user-bound key
///
/// # Arguments
/// * `key_name` - Name of the Windows Hello credential
/// * `cache_config` - Expected cache configuration
/// * `message` - Message to display during Windows Hello prompt
/// * `window_id` - Window ID for the prompt
/// * `sealed_bound_key_bytes` - Previously sealed key material
/// * `needs_reseal` - Output: whether the key needs to be resealed
///
/// # Returns
/// The decrypted user key bytes
pub fn load_user_bound_key(
    key_name: &str,
    cache_config: &keyCredentialCacheConfig,
    message: &str,
    window_id: u64,
    sealed_bound_key_bytes: &[u8],
) -> Result<(Vec<u8>, bool), UserBoundKeyError> {
    // Unseal the bound key
    let (bound_key_bytes, unseal_flags) = unseal_data(sealed_bound_key_bytes)?;

    // Check if key is stale
    if is_stale_key(unseal_flags) {
        return Err(UserBoundKeyError::StaleKey);
    }

    // Extract ephemeral public key from bound key structure
    let ephemeral_public_key = get_ephemeral_public_key_bytes_from_bound_key(&bound_key_bytes)?;

    // Format the key name
    let formatted_key_name = untrusted::userboundkey_format_key_name(&key_name.into())
        .map_err(|e| UserBoundKeyError::AbiError(e))?;

    // Security validation
    validate_formatted_key_name(&formatted_key_name, key_name)?;

    // Get enclave base address
    let enclave_ptr = get_enclave_base_address_u64()?;

    // Establish session for load (calls VTL0)
    let credential_and_session = untrusted::userboundkey_establish_session_for_load(
        enclave_ptr,
        &key_name.into(),
        &message.into(),
        window_id,
    )
    .map_err(|e| UserBoundKeyError::AbiError(e))?;

    // RAII wrappers
    let credential = UniqueCredential::new(credential_and_session.credential);
    let session_handle = UniqueSessionHandle::new(
        credential_and_session.sessionInfo as USER_BOUND_KEY_SESSION_HANDLE,
    );

    // Create encrypted request for RetrieveAuthorizationContext
    let mut encrypted_rac_ptr: *mut core::ffi::c_void = core::ptr::null_mut();
    let mut encrypted_rac_size: u32 = 0;
    let mut local_nonce: u64 = 0;

    let formatted_key_name_wide: Vec<u16> = formatted_key_name
        .encode_utf16()
        .chain(core::iter::once(0))
        .collect();

    unsafe {
        let hr = CreateUserBoundKeyRequestForRetrieveAuthorizationContext(
            session_handle.get(),
            formatted_key_name_wide.as_ptr(),
            &mut local_nonce,
            &mut encrypted_rac_ptr,
            &mut encrypted_rac_size,
        );
        check_hr(hr)?;
    }

    let encrypted_rac_request = unsafe {
        core::slice::from_raw_parts(encrypted_rac_ptr as *const u8, encrypted_rac_size as usize)
            .to_vec()
    };

    unsafe {
        let heap = GetProcessHeap();
        HeapFree(heap, 0, encrypted_rac_ptr);
    }

    // Get authorization context (calls VTL0)
    let auth_context_blob = untrusted::userboundkey_get_authorization_context_from_credential(
        credential.get(),
        &encrypted_rac_request,
        &message.into(),
        window_id,
    )
    .map_err(|e| UserBoundKeyError::AbiError(e))?;

    // Get auth context handle
    let mut auth_context_handle: USER_BOUND_KEY_AUTH_CONTEXT_HANDLE = core::ptr::null_mut();
    unsafe {
        let hr = GetUserBoundKeyAuthContext(
            session_handle.get(),
            auth_context_blob.as_ptr() as *const core::ffi::c_void,
            auth_context_blob.len() as u32,
            local_nonce,
            &mut auth_context_handle,
        );
        check_hr(hr)?;
    }
    let auth_context = UniqueAuthContextHandle(auth_context_handle);

    // Validate auth context
    let prop = USER_BOUND_KEY_AUTH_CONTEXT_PROPERTY {
        name: USER_BOUND_KEY_AUTH_CONTEXT_PROPERTY_NAME::UserBoundKeyAuthContextPropertyCacheConfig,
        size: core::mem::size_of::<keyCredentialCacheConfig>() as u32,
        value: cache_config as *const _ as *mut core::ffi::c_void,
    };

    unsafe {
        let hr = ValidateUserBoundKeyAuthContext(
            formatted_key_name_wide.as_ptr(),
            auth_context.get(),
            1,
            &prop,
        );
        check_hr(hr)?;
    }

    // Create encrypted request for DeriveSharedSecret
    let mut encrypted_dss_ptr: *mut core::ffi::c_void = core::ptr::null_mut();
    let mut encrypted_dss_size: u32 = 0;

    unsafe {
        let hr = CreateUserBoundKeyRequestForDeriveSharedSecret(
            session_handle.get(),
            formatted_key_name_wide.as_ptr(),
            ephemeral_public_key.as_ptr() as *const core::ffi::c_void,
            ephemeral_public_key.len() as u32,
            &mut local_nonce,
            &mut encrypted_dss_ptr,
            &mut encrypted_dss_size,
        );
        check_hr(hr)?;
    }

    let encrypted_dss_request = unsafe {
        core::slice::from_raw_parts(encrypted_dss_ptr as *const u8, encrypted_dss_size as usize)
            .to_vec()
    };

    unsafe {
        let heap = GetProcessHeap();
        HeapFree(heap, 0, encrypted_dss_ptr);
    }

    // Get secret from credential (calls VTL0 - prompts for Windows Hello)
    let secret = untrusted::userboundkey_get_secret_from_credential(
        credential.get(),
        &encrypted_dss_request,
        &message.into(),
        window_id,
    )
    .map_err(|e| UserBoundKeyError::AbiError(e))?;

    // Unprotect the user key
    let mut user_key_ptr: *mut core::ffi::c_void = core::ptr::null_mut();
    let mut user_key_size: u32 = 0;

    unsafe {
        let hr = UnprotectUserBoundKey(
            session_handle.get(),
            auth_context.get(),
            secret.as_ptr() as *const core::ffi::c_void,
            secret.len() as u32,
            bound_key_bytes.as_ptr() as *const core::ffi::c_void,
            bound_key_bytes.len() as u32,
            local_nonce,
            &mut user_key_ptr,
            &mut user_key_size,
        );
        check_hr(hr)?;
    }

    let user_key_bytes = unsafe {
        core::slice::from_raw_parts(user_key_ptr as *const u8, user_key_size as usize).to_vec()
    };

    unsafe {
        let heap = GetProcessHeap();
        HeapFree(heap, 0, user_key_ptr);
    }

    Ok((user_key_bytes, false))
}

/// Reseal a user-bound key with current enclave identity
///
/// This is used when load_user_bound_key returns StaleKey error,
/// indicating the sealing key has changed. The caller should have
/// already unsealed the data (which succeeds even with a stale key)
/// and passes the unsealed bound key bytes to this function.
///
/// # Arguments
/// * `bound_key_bytes` - Previously unsealed bound key bytes (not sealed)
/// * `sealing_policy` - Enclave sealing identity policy for the new seal
/// * `runtime_policy` - Runtime policy flags
///
/// # Returns
/// Newly sealed key material
pub fn reseal_user_bound_key(
    bound_key_bytes: &[u8],
    sealing_policy: EnclaveSealingIdentityPolicy,
    runtime_policy: u32,
) -> Result<Vec<u8>, UserBoundKeyError> {
    // Re-seal with current enclave identity
    let resealed_data = seal_data(bound_key_bytes, sealing_policy, runtime_policy)?;

    Ok(resealed_data)
}

/// Implementation of the Trusted trait for EDL-generated code
pub struct TrustedImpl;

#[allow(non_snake_case)]
impl Trusted for TrustedImpl {
    fn userboundkey_get_attestation_report(
        challenge: &Vec<u8>,
    ) -> Result<attestationReportAndSessionInfo, userboundkey_enclave_gen::AbiError> {
        unsafe {
            let mut report_ptr: *mut core::ffi::c_void = core::ptr::null_mut();
            let mut report_size: u32 = 0;
            let mut session_handle: USER_BOUND_KEY_SESSION_HANDLE = core::ptr::null_mut();

            let hr = InitializeUserBoundKeySession(
                challenge.as_ptr() as *const core::ffi::c_void,
                challenge.len() as u32,
                &mut report_ptr,
                &mut report_size,
                &mut session_handle,
            );

            if hr < 0 {
                return Err(userboundkey_enclave_gen::AbiError::Hresult(hr));
            }

            // Convert report to Vec
            let report =
                core::slice::from_raw_parts(report_ptr as *const u8, report_size as usize).to_vec();

            // Free the allocated memory
            let heap = GetProcessHeap();
            HeapFree(heap, 0, report_ptr);

            Ok(attestationReportAndSessionInfo {
                report,
                sessionInfo: session_handle as u64,
            })
        }
    }

    fn userboundkey_close_session(
        sessionInfo: u64,
    ) -> Result<(), userboundkey_enclave_gen::AbiError> {
        if sessionInfo != 0 {
            unsafe {
                let session_handle = sessionInfo as USER_BOUND_KEY_SESSION_HANDLE;
                let hr = CloseUserBoundKeySession(session_handle);
                if hr < 0 {
                    return Err(userboundkey_enclave_gen::AbiError::Hresult(hr));
                }
            }
        }
        Ok(())
    }
}
