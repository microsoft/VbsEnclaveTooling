// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

// Temporary veinterop_kcm.h replacement header until the official header is unavailable.
// Having this header allows the enclave and host code to compile without depending on the
// official veinterop_kcm.h header.

DECLARE_HANDLE(USER_BOUND_KEY_AUTH_CONTEXT_HANDLE);

DECLARE_HANDLE(USER_BOUND_KEY_SESSION_HANDLE);

typedef enum _USER_BOUND_KEY_AUTH_CONTEXT_PROPERTY_NAME {
    UserBoundKeyAuthContextPropertyCacheConfig = 0,
} USER_BOUND_KEY_AUTH_CONTEXT_PROPERTY_NAME;

typedef struct _USER_BOUND_KEY_AUTH_CONTEXT_PROPERTY
{
    USER_BOUND_KEY_AUTH_CONTEXT_PROPERTY_NAME name;
    UINT32 size;
    _Field_size_bytes_(size) void* value;
} USER_BOUND_KEY_AUTH_CONTEXT_PROPERTY, * PUSER_BOUND_KEY_AUTH_CONTEXT_PROPERTY;

inline HRESULT InitializeUserBoundKeySession(
    _In_reads_bytes_(challengeSize) const void* challenge,
    _In_ UINT32 challengeSize,
    _Outptr_result_buffer_(*reportSize) void** report,
    _Out_ UINT32* reportSize,
    _Out_ USER_BOUND_KEY_SESSION_HANDLE* sessionHandle)
{
    UNREFERENCED_PARAMETER(challenge);
    UNREFERENCED_PARAMETER(challengeSize);
    UNREFERENCED_PARAMETER(report);
    UNREFERENCED_PARAMETER(reportSize);
    UNREFERENCED_PARAMETER(sessionHandle);
    return E_NOTIMPL;
}

inline HRESULT CreateUserBoundKeyRequestForRetrieveAuthorizationContext(
    _Inout_ USER_BOUND_KEY_SESSION_HANDLE sessionHandle,
    _In_ PCWSTR keyName,
    _Out_ UINT64* nonce,
    _Outptr_result_buffer_(*encryptedRequestSize) void** encryptedRequest,
    _Out_ UINT32* encryptedRequestSize)
{
    UNREFERENCED_PARAMETER(sessionHandle);
    UNREFERENCED_PARAMETER(keyName);
    UNREFERENCED_PARAMETER(nonce);
    UNREFERENCED_PARAMETER(encryptedRequest);
    UNREFERENCED_PARAMETER(encryptedRequestSize);
    return E_NOTIMPL;
}

inline HRESULT GetUserBoundKeyAuthContext(
    _In_ USER_BOUND_KEY_SESSION_HANDLE sessionHandle,
    _In_reads_bytes_(authContextBlobSize) const void* authContextBlob,
    _In_ UINT32 authContextBlobSize,
    _In_ UINT64 nonce,
    _Out_ USER_BOUND_KEY_AUTH_CONTEXT_HANDLE* authContextHandle)
{
    UNREFERENCED_PARAMETER(sessionHandle);
    UNREFERENCED_PARAMETER(authContextBlob);
    UNREFERENCED_PARAMETER(authContextBlobSize);
    UNREFERENCED_PARAMETER(nonce);
    UNREFERENCED_PARAMETER(authContextHandle);
    return E_NOTIMPL;
}

inline HRESULT ValidateUserBoundKeyAuthContext(
    _In_ PCWSTR keyName,
    _In_ USER_BOUND_KEY_AUTH_CONTEXT_HANDLE authContextHandle,
    _In_ UINT32 count,
    _In_reads_(count) const USER_BOUND_KEY_AUTH_CONTEXT_PROPERTY* values)
{
    UNREFERENCED_PARAMETER(keyName);
    UNREFERENCED_PARAMETER(authContextHandle);
    UNREFERENCED_PARAMETER(count);
    UNREFERENCED_PARAMETER(values);
    return E_NOTIMPL;
}

inline HRESULT ProtectUserBoundKey(
    _In_ USER_BOUND_KEY_AUTH_CONTEXT_HANDLE authContext,
    _In_reads_bytes_(userKeySize) const void* userKey,
    _In_ UINT32 userKeySize,
    _Outptr_result_buffer_(*boundKeySize) void** boundKey,
    _Inout_ UINT32* boundKeySize)
{
    UNREFERENCED_PARAMETER(authContext);
    UNREFERENCED_PARAMETER(userKey);
    UNREFERENCED_PARAMETER(userKeySize);
    UNREFERENCED_PARAMETER(boundKey);
    UNREFERENCED_PARAMETER(boundKeySize);
    return E_NOTIMPL;
}

inline HRESULT CloseUserBoundKeyAuthContext(
    _In_ USER_BOUND_KEY_AUTH_CONTEXT_HANDLE handle)
{
    UNREFERENCED_PARAMETER(handle);
    return E_NOTIMPL;
}

inline HRESULT CloseUserBoundKeySession(
        _In_ USER_BOUND_KEY_SESSION_HANDLE sessionHandle
)
{
    UNREFERENCED_PARAMETER(sessionHandle);
    return E_NOTIMPL;
}

inline HRESULT CreateUserBoundKeyRequestForDeriveSharedSecret(
    _Inout_ USER_BOUND_KEY_SESSION_HANDLE sessionHandle,
    _In_ PCWSTR keyName,
    _In_reads_bytes_(publicKeyBytesSize) const void* publicKeyBytes,
    _In_ UINT32 publicKeyBytesSize,
    _Out_ UINT64* nonce,
    _Outptr_result_buffer_(*encryptedRequestSize) void** encryptedRequest,
    _Out_ UINT32* encryptedRequestSize)
{
    UNREFERENCED_PARAMETER(sessionHandle);
    UNREFERENCED_PARAMETER(keyName);
    UNREFERENCED_PARAMETER(publicKeyBytes);
    UNREFERENCED_PARAMETER(publicKeyBytesSize);
    UNREFERENCED_PARAMETER(nonce);
    UNREFERENCED_PARAMETER(encryptedRequest);
    UNREFERENCED_PARAMETER(encryptedRequestSize);
    return E_NOTIMPL;
}

inline HRESULT UnprotectUserBoundKey(
    _In_ USER_BOUND_KEY_SESSION_HANDLE sessionHandle,
    _In_ USER_BOUND_KEY_AUTH_CONTEXT_HANDLE authContext,
    _In_reads_bytes_(sessionEncryptedDerivedSecretSize) const void* sessionEncryptedDerivedSecret,
    _In_ UINT32 sessionEncryptedDerivedSecretSize,
    _In_reads_bytes_(encryptedUserBoundKeySize) const void* encryptedUserBoundKey,
    _In_ UINT32 encryptedUserBoundKeySize,
    _In_ UINT64 nonce,
    _Outptr_result_buffer_(*userKeySize) void** userKey,
    _Inout_ UINT32* userKeySize)
{
    UNREFERENCED_PARAMETER(sessionHandle);
    UNREFERENCED_PARAMETER(authContext);
    UNREFERENCED_PARAMETER(sessionEncryptedDerivedSecret);
    UNREFERENCED_PARAMETER(sessionEncryptedDerivedSecretSize);
    UNREFERENCED_PARAMETER(encryptedUserBoundKey);
    UNREFERENCED_PARAMETER(encryptedUserBoundKeySize);
    UNREFERENCED_PARAMETER(nonce);
    UNREFERENCED_PARAMETER(userKey);
    UNREFERENCED_PARAMETER(userKeySize);
    return E_NOTIMPL;
}
