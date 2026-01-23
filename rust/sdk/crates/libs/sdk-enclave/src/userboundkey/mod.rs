// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! VTL1 User-Bound Key Implementation
//!
//! Implements enclave-side user-bound key operations using VBS enclave sealing
//! and the veinterop.dll APIs for KCM (Key Credential Manager) interactions.

mod crypto;
mod types;

pub use crypto::{
    EnclaveSealingIdentityPolicy, NONCE_SIZE, SYMMETRIC_KEY_SIZE_BYTES, SymmetricKeyHandle,
    TAG_SIZE, ZERO_NONCE, decrypt, encrypt,
};
pub use types::*;

// Re-export the cache config type for use by samples
pub use sdk_enclave_gen::implementation::types::keyCredentialCacheConfig;

// Re-export widestring types for public API consumers
pub use widestring::U16Str;

use alloc::vec::Vec;

use sdk_enclave_gen::AbiError;
use sdk_enclave_gen::implementation::types::attestationReportAndSessionInfo;
use sdk_enclave_gen::stubs::untrusted;
use widestring::U16String;

use windows_enclave::veinterop::{
    CloseUserBoundKeyAuthContext, CloseUserBoundKeySession,
    CreateUserBoundKeyRequestForDeriveSharedSecret,
    CreateUserBoundKeyRequestForRetrieveAuthorizationContext, GetUserBoundKeyAuthContext,
    InitializeUserBoundKeySession, ProtectUserBoundKey, USER_BOUND_KEY_AUTH_CONTEXT_HANDLE,
    USER_BOUND_KEY_AUTH_CONTEXT_PROPERTY, USER_BOUND_KEY_AUTH_CONTEXT_PROPERTY_NAME,
    USER_BOUND_KEY_SESSION_HANDLE, UnprotectUserBoundKey, ValidateUserBoundKeyAuthContext,
};
use windows_enclave::vertdll::{GetProcessHeap, HeapFree};

use crate::common::get_enclave_base_address_u64;
use crypto::{check_hr, generate_symmetric_key_bytes, is_stale_key, seal_data, unseal_data};

// BCrypt algorithm pseudo-handle value from Windows SDK bcrypt.h.
// BCRYPT_ECDH_P384_ALG_HANDLE = ((BCRYPT_ALG_HANDLE) 0x000002b1)
// Stored as u64 for EDL interface compatibility.
const BCRYPT_ECDH_P384_ALG_HANDLE_U64: u64 = 0x000002b1;

/// RAII wrapper for heap-allocated buffers returned by veinterop APIs.
/// Automatically frees the buffer via HeapFree when dropped.
struct HeapBuffer {
    ptr: *mut core::ffi::c_void,
    size: u32,
}

impl HeapBuffer {
    /// Takes ownership of a heap-allocated buffer.
    ///
    /// # Safety
    /// The pointer must have been allocated via GetProcessHeap/HeapAlloc
    /// and the size must be accurate.
    unsafe fn from_raw(ptr: *mut core::ffi::c_void, size: u32) -> Self {
        Self { ptr, size }
    }

    /// Returns true if the buffer is null or empty.
    fn is_empty(&self) -> bool {
        self.ptr.is_null() || self.size == 0
    }

    /// Copies the buffer contents to a Vec.
    fn to_vec(&self) -> Vec<u8> {
        if self.is_empty() {
            return Vec::new();
        }
        unsafe { core::slice::from_raw_parts(self.ptr as *const u8, self.size as usize).to_vec() }
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

/// Validate that formatted key name ends with expected suffix (wide string version)
fn validate_formatted_key_name_wide(
    formatted_key_name: &U16Str,
    original_key_name: &U16Str,
) -> Result<(), UserBoundKeyError> {
    // Build expected suffix: "//" + original_key_name
    let slash_slash = U16String::from_str("//");
    let expected_suffix_len = 2 + original_key_name.len();

    if formatted_key_name.len() < expected_suffix_len {
        return Err(UserBoundKeyError::SecurityViolation(
            "Formatted key name does not match expected pattern",
        ));
    }

    // Check if formatted_key_name ends with "//{original_key_name}"
    let suffix_start = formatted_key_name.len() - expected_suffix_len;
    let formatted_suffix = &formatted_key_name.as_slice()[suffix_start..];

    if formatted_suffix[0..2] != slash_slash.as_slice()[..]
        || formatted_suffix[2..] != *original_key_name.as_slice()
    {
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
/// * `key_name` - Name for the Windows Hello credential (UTF-16 wide string without null terminator)
/// * `cache_config` - Cache configuration for the credential
/// * `message` - Message to display during Windows Hello prompt (UTF-16 wide string without null terminator)
/// * `window_id` - Window ID for the prompt
/// * `sealing_policy` - Enclave sealing identity policy
/// * `runtime_policy` - Runtime policy flags
/// * `key_credential_creation_option` - Credential creation options
///
/// # Returns
/// Sealed key material that can be stored and later loaded
pub fn create_user_bound_key(
    key_name: &U16Str,
    cache_config: &keyCredentialCacheConfig,
    message: &U16Str,
    window_id: u64,
    sealing_policy: EnclaveSealingIdentityPolicy,
    runtime_policy: u32,
    key_credential_creation_option: u32,
) -> Result<Vec<u8>, UserBoundKeyError> {
    // Generate symmetric key
    let user_key_bytes = generate_symmetric_key_bytes(SYMMETRIC_KEY_SIZE_BYTES)?;

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
#[allow(clippy::too_many_arguments)]
pub fn create_user_bound_key_with_custom_key(
    key_name: &U16Str,
    cache_config: &keyCredentialCacheConfig,
    message: &U16Str,
    window_id: u64,
    sealing_policy: EnclaveSealingIdentityPolicy,
    runtime_policy: u32,
    key_credential_creation_option: u32,
    custom_key_bytes: &[u8],
) -> Result<Vec<u8>, UserBoundKeyError> {
    // Format the key name (calls VTL0) - this is the FIRST VTL0 call
    // Create WString from key_name slice
    let key_name_wstring = sdk_enclave_gen::implementation::types::edl::WString {
        wchars: key_name.as_slice().to_vec(),
    };
    let formatted_key_name_wstring = untrusted::userboundkey_format_key_name(&key_name_wstring)
        .map_err(UserBoundKeyError::AbiError)?;

    // Security validation (wide string version)
    let formatted_key_name_u16str = U16Str::from_slice(&formatted_key_name_wstring.wchars);
    validate_formatted_key_name_wide(formatted_key_name_u16str, key_name)?;

    // Get enclave base address
    let enclave_ptr = get_enclave_base_address_u64()?;

    // Create WString for message
    let message_wstring = sdk_enclave_gen::implementation::types::edl::WString {
        wchars: message.as_slice().to_vec(),
    };

    // Establish session (calls VTL0 which triggers Windows Hello)
    // Requires at least 2 enclave threads - one for this call and one for the callback
    let credential_and_session = untrusted::userboundkey_establish_session_for_create(
        enclave_ptr,
        &key_name_wstring,
        BCRYPT_ECDH_P384_ALG_HANDLE_U64,
        &message_wstring,
        window_id,
        cache_config,
        key_credential_creation_option,
    )
    .map_err(UserBoundKeyError::AbiError)?;

    // RAII wrappers for cleanup
    let credential = UniqueCredential::new(credential_and_session.credential);
    let session_handle = UniqueSessionHandle::new(
        credential_and_session.sessionInfo as USER_BOUND_KEY_SESSION_HANDLE,
    );

    // Create encrypted KCM request for RetrieveAuthorizationContext
    let mut encrypted_request_ptr: *mut core::ffi::c_void = core::ptr::null_mut();
    let mut encrypted_request_size: u32 = 0;
    let mut local_nonce: u64 = 0;

    // Create null-terminated wide string for Windows API
    let formatted_key_name_with_null = U16String::from(formatted_key_name_u16str);

    unsafe {
        let hr = CreateUserBoundKeyRequestForRetrieveAuthorizationContext(
            session_handle.get(),
            formatted_key_name_with_null.as_ptr(),
            &mut local_nonce,
            &mut encrypted_request_ptr,
            &mut encrypted_request_size,
        );
        check_hr(hr)?;
    }

    // Take ownership of the heap-allocated buffer
    let encrypted_request_buf =
        unsafe { HeapBuffer::from_raw(encrypted_request_ptr, encrypted_request_size) };

    // Defensive check - API contract guarantees valid output on S_OK
    if encrypted_request_buf.is_empty() {
        return Err(UserBoundKeyError::InvalidData("API returned empty request"));
    }

    // Convert to Vec (HeapBuffer will free on drop)
    let encrypted_request = encrypted_request_buf.to_vec();

    // Get authorization context from credential (calls VTL0)
    let auth_context_blob = untrusted::userboundkey_get_authorization_context_from_credential(
        credential.get(),
        &encrypted_request,
        &message_wstring,
        window_id,
    )
    .map_err(UserBoundKeyError::AbiError)?;

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
            formatted_key_name_with_null.as_ptr(),
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

    // Take ownership of the heap-allocated buffer
    let bound_key_buf = unsafe { HeapBuffer::from_raw(bound_key_ptr, bound_key_size) };

    // Defensive check - API contract guarantees valid output on S_OK
    if bound_key_buf.is_empty() {
        return Err(UserBoundKeyError::InvalidData(
            "API returned empty bound key",
        ));
    }

    // Convert bound key to Vec (HeapBuffer will free on drop)
    let bound_key_bytes = bound_key_buf.to_vec();

    // Seal the bound key
    let sealed_key = seal_data(&bound_key_bytes, sealing_policy, runtime_policy)?;

    Ok(sealed_key)
}

/// Load a previously created user-bound key
///
/// # Arguments
/// * `key_name` - Name of the Windows Hello credential (UTF-16 wide string without null terminator)
/// * `cache_config` - Expected cache configuration
/// * `message` - Message to display during Windows Hello prompt (UTF-16 wide string without null terminator)
/// * `window_id` - Window ID for the prompt
/// * `sealed_bound_key_bytes` - Previously sealed key material
///
/// # Returns
/// A tuple of (decrypted user key bytes, needs_reseal flag).
/// If `needs_reseal` is true, the caller should reseal the key with [`reseal_user_bound_key`].
pub fn load_user_bound_key(
    key_name: &U16Str,
    cache_config: &keyCredentialCacheConfig,
    message: &U16Str,
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

    // Format the key name (calls VTL0)
    let key_name_wstring = sdk_enclave_gen::implementation::types::edl::WString {
        wchars: key_name.as_slice().to_vec(),
    };
    let formatted_key_name_wstring = untrusted::userboundkey_format_key_name(&key_name_wstring)
        .map_err(UserBoundKeyError::AbiError)?;

    // Security validation (wide string version)
    let formatted_key_name_u16str = U16Str::from_slice(&formatted_key_name_wstring.wchars);
    validate_formatted_key_name_wide(formatted_key_name_u16str, key_name)?;

    // Get enclave base address
    let enclave_ptr = get_enclave_base_address_u64()?;

    // Create WString for message
    let message_wstring = sdk_enclave_gen::implementation::types::edl::WString {
        wchars: message.as_slice().to_vec(),
    };

    // Establish session for load (calls VTL0)
    let credential_and_session = untrusted::userboundkey_establish_session_for_load(
        enclave_ptr,
        &key_name_wstring,
        &message_wstring,
        window_id,
    )
    .map_err(UserBoundKeyError::AbiError)?;

    // RAII wrappers
    let credential = UniqueCredential::new(credential_and_session.credential);
    let session_handle = UniqueSessionHandle::new(
        credential_and_session.sessionInfo as USER_BOUND_KEY_SESSION_HANDLE,
    );

    // Create encrypted request for RetrieveAuthorizationContext
    let mut encrypted_rac_ptr: *mut core::ffi::c_void = core::ptr::null_mut();
    let mut encrypted_rac_size: u32 = 0;
    let mut local_nonce: u64 = 0;

    // Create null-terminated wide string for Windows API
    let formatted_key_name_with_null = U16String::from(formatted_key_name_u16str);

    unsafe {
        let hr = CreateUserBoundKeyRequestForRetrieveAuthorizationContext(
            session_handle.get(),
            formatted_key_name_with_null.as_ptr(),
            &mut local_nonce,
            &mut encrypted_rac_ptr,
            &mut encrypted_rac_size,
        );
        check_hr(hr)?;
    }

    // Take ownership of the heap-allocated buffer
    let encrypted_rac_buf = unsafe { HeapBuffer::from_raw(encrypted_rac_ptr, encrypted_rac_size) };

    // Defensive check - API contract guarantees valid output on S_OK
    if encrypted_rac_buf.is_empty() {
        return Err(UserBoundKeyError::InvalidData("API returned empty request"));
    }

    // Convert to Vec (HeapBuffer will free on drop)
    let encrypted_rac_request = encrypted_rac_buf.to_vec();

    // Get authorization context (calls VTL0)
    let auth_context_blob = untrusted::userboundkey_get_authorization_context_from_credential(
        credential.get(),
        &encrypted_rac_request,
        &message_wstring,
        window_id,
    )
    .map_err(UserBoundKeyError::AbiError)?;

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
            formatted_key_name_with_null.as_ptr(),
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
            formatted_key_name_with_null.as_ptr(),
            ephemeral_public_key.as_ptr() as *const core::ffi::c_void,
            ephemeral_public_key.len() as u32,
            &mut local_nonce,
            &mut encrypted_dss_ptr,
            &mut encrypted_dss_size,
        );
        check_hr(hr)?;
    }

    // Take ownership of the heap-allocated buffer
    let encrypted_dss_buf = unsafe { HeapBuffer::from_raw(encrypted_dss_ptr, encrypted_dss_size) };

    // Defensive check - API contract guarantees valid output on S_OK
    if encrypted_dss_buf.is_empty() {
        return Err(UserBoundKeyError::InvalidData("API returned empty request"));
    }

    // Convert to Vec (HeapBuffer will free on drop)
    let encrypted_dss_request = encrypted_dss_buf.to_vec();

    // Get secret from credential (calls VTL0 - prompts for Windows Hello)
    let secret = untrusted::userboundkey_get_secret_from_credential(
        credential.get(),
        &encrypted_dss_request,
        &message_wstring,
        window_id,
    )
    .map_err(UserBoundKeyError::AbiError)?;

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

    // Take ownership of the heap-allocated buffer
    let user_key_buf = unsafe { HeapBuffer::from_raw(user_key_ptr, user_key_size) };

    // Defensive check - API contract guarantees valid output on S_OK
    if user_key_buf.is_empty() {
        return Err(UserBoundKeyError::InvalidData(
            "API returned empty user key",
        ));
    }

    // Convert to Vec (HeapBuffer will free on drop)
    let user_key_bytes = user_key_buf.to_vec();

    Ok((user_key_bytes, false))
}

/// Reseal a user-bound key with current enclave identity
///
/// This function re-seals data that was previously sealed by an older enclave version.
/// It is used when the sealing key has rotated (detected by `is_stale_key` flag from unsealing).
///
/// Note: The input `bound_key_bytes` should be the unsealed (decrypted) bound key data,
/// NOT the sealed blob. If you have sealed data, first unseal it with `unseal_data`
/// from the crypto module, then pass the unsealed result here.
///
/// # Arguments
/// * `bound_key_bytes` - Previously unsealed bound key bytes (NOT sealed data)
/// * `sealing_policy` - Enclave sealing identity policy for the new seal
/// * `runtime_policy` - Runtime policy flags
///
/// # Returns
/// Newly sealed key material that can be stored and used with future loads
pub fn reseal_user_bound_key(
    bound_key_bytes: &[u8],
    sealing_policy: EnclaveSealingIdentityPolicy,
    runtime_policy: u32,
) -> Result<Vec<u8>, UserBoundKeyError> {
    // Re-seal with current enclave identity
    let resealed_data = seal_data(bound_key_bytes, sealing_policy, runtime_policy)?;

    Ok(resealed_data)
}

/// Get attestation report for a challenge and initialize a user-bound key session.
///
/// This is the trusted implementation called from the EDL interface.
#[allow(non_snake_case)]
#[allow(clippy::ptr_arg)] // Signature must match EDL-generated trait
pub fn userboundkey_get_attestation_report(
    challenge: &Vec<u8>,
) -> Result<attestationReportAndSessionInfo, AbiError> {
    let mut report_ptr: *mut core::ffi::c_void = core::ptr::null_mut();
    let mut report_size: u32 = 0;
    let mut session_handle: USER_BOUND_KEY_SESSION_HANDLE = core::ptr::null_mut();

    let hr = unsafe {
        InitializeUserBoundKeySession(
            challenge.as_ptr() as *const core::ffi::c_void,
            challenge.len() as u32,
            &mut report_ptr,
            &mut report_size,
            &mut session_handle,
        )
    };

    if hr < 0 {
        return Err(AbiError::Hresult(hr));
    }

    // Take ownership of the heap-allocated buffer
    let report_buf = unsafe { HeapBuffer::from_raw(report_ptr, report_size) };

    // Defensive check - API contract guarantees valid output on S_OK
    if report_buf.is_empty() {
        return Err(AbiError::Hresult(-1));
    }

    // Convert report to Vec (HeapBuffer will free on drop)
    let report = report_buf.to_vec();

    Ok(attestationReportAndSessionInfo {
        report,
        sessionInfo: session_handle as u64,
    })
}

/// Close a user-bound key session and release associated resources.
///
/// This is the trusted implementation called from the EDL interface.
#[allow(non_snake_case)]
pub fn userboundkey_close_session(sessionInfo: u64) -> Result<(), AbiError> {
    if sessionInfo != 0 {
        unsafe {
            let session_handle = sessionInfo as USER_BOUND_KEY_SESSION_HANDLE;
            let hr = CloseUserBoundKeySession(session_handle);
            if hr < 0 {
                return Err(AbiError::Hresult(hr));
            }
        }
    }
    Ok(())
}
