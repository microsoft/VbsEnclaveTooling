// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::vertdll::*;

// The following types in VEINTEROP.DLL should be generated but are not currently included in the Win32 metadata.
// We manually define them here based on the content of veinterop_kcm.h.

pub type USER_BOUND_KEY_SESSION_HANDLE = *mut core::ffi::c_void;
pub type USER_BOUND_KEY_AUTH_CONTEXT_HANDLE = *mut core::ffi::c_void;

#[repr(i32)]
#[derive(Copy, Clone)]
pub enum USER_BOUND_KEY_AUTH_CONTEXT_PROPERTY_NAME {
    UserBoundKeyAuthContextPropertyCacheConfig = 0,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct USER_BOUND_KEY_AUTH_CONTEXT_PROPERTY {
    pub name: USER_BOUND_KEY_AUTH_CONTEXT_PROPERTY_NAME,
    pub size: u32,
    pub value: *mut core::ffi::c_void,
}

windows_link::link!("veinterop.dll" "system" fn InitializeUserBoundKeySession(
    challenge: *const core::ffi::c_void,
    challengeSize: u32,
    report: *mut *mut core::ffi::c_void,
    reportSize: *mut u32,
    sessionHandle: *mut USER_BOUND_KEY_SESSION_HANDLE
) -> HRESULT);

windows_link::link!("veinterop.dll" "system" fn CreateUserBoundKeyRequestForRetrieveAuthorizationContext(
    sessionHandle: USER_BOUND_KEY_SESSION_HANDLE,
    keyName: PCWSTR,
    nonce: *mut u64,
    encryptedRequest: *mut *mut core::ffi::c_void,
    encryptedRequestSize: *mut u32
) -> HRESULT);

windows_link::link!("veinterop.dll" "system" fn GetUserBoundKeyAuthContext(
    sessionHandle: USER_BOUND_KEY_SESSION_HANDLE,
    authContextBlob: *const core::ffi::c_void,
    authContextBlobSize: u32,
    nonce: u64,
    authContextHandle: *mut USER_BOUND_KEY_AUTH_CONTEXT_HANDLE
) -> HRESULT);

windows_link::link!("veinterop.dll" "system" fn ValidateUserBoundKeyAuthContext(
    keyName: PCWSTR,
    authContextHandle: USER_BOUND_KEY_AUTH_CONTEXT_HANDLE,
    count: u32,
    values: *const USER_BOUND_KEY_AUTH_CONTEXT_PROPERTY
) -> HRESULT);

windows_link::link!("veinterop.dll" "system" fn ProtectUserBoundKey(
    authContext: USER_BOUND_KEY_AUTH_CONTEXT_HANDLE,
    userKey: *const core::ffi::c_void,
    userKeySize: u32,
    boundKey: *mut *mut core::ffi::c_void,
    boundKeySize: *mut u32
) -> HRESULT);

windows_link::link!("veinterop.dll" "system" fn CloseUserBoundKeyAuthContext(
    handle: USER_BOUND_KEY_AUTH_CONTEXT_HANDLE
) -> HRESULT);

windows_link::link!("veinterop.dll" "system" fn CloseUserBoundKeySession(
    sessionHandle: USER_BOUND_KEY_SESSION_HANDLE
) -> HRESULT);

windows_link::link!("veinterop.dll" "system" fn CreateUserBoundKeyRequestForDeriveSharedSecret(
    sessionHandle: USER_BOUND_KEY_SESSION_HANDLE,
    keyName: PCWSTR,
    publicKeyBytes: *const core::ffi::c_void,
    publicKeyBytesSize: u32,
    nonce: *mut u64,
    encryptedRequest: *mut *mut core::ffi::c_void,
    encryptedRequestSize: *mut u32
) -> HRESULT);

windows_link::link!("veinterop.dll" "system" fn UnprotectUserBoundKey(
    sessionHandle: USER_BOUND_KEY_SESSION_HANDLE,
    authContext: USER_BOUND_KEY_AUTH_CONTEXT_HANDLE,
    sessionEncryptedDerivedSecret: *const core::ffi::c_void,
    sessionEncryptedDerivedSecretSize: u32,
    encryptedUserBoundKey: *const core::ffi::c_void,
    encryptedUserBoundKeySize: u32,
    nonce: u64,
    userKey: *mut *mut core::ffi::c_void,
    userKeySize: *mut u32
) -> HRESULT);
