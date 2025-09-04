#pragma once

#ifndef VENGCDLL_H
#define VENGCDLL_H

#include <windows.h>
#include <sal.h>
#include <bcrypt.h>

// Include necessary headers for enclave APIs
#include <winenclaveapi.h>
#include <ntenclv.h>
#include <enclaveium.h>

// KCM Trustlet Identity constant
#ifndef TRUSTLETIDENTITY_KCM
#define TRUSTLETIDENTITY_KCM 6
#endif

// AES-GCM constants
#define AES_GCM_NONCE_SIZE 12
#define AES_GCM_TAG_SIZE 16

// Cryptographic constants
#define ECDH_P384_KEY_SIZE_BITS 384         // ECDH P-384 key size in bits
#define AES_256_KEY_SIZE_BYTES 32           // AES-256 session key size in bytes

// Buffer size constants
#define KCM_KEY_NAME_BUFFER_SIZE 256        // Buffer size for key names
#define KCM_ATTESTATION_BUFFER_SIZE 256     // Buffer size for attestation data

// KCM public key validation limits
#define KCM_PUBLIC_KEY_MIN_SIZE 32          // Minimum allowed KCM public key size
#define KCM_PUBLIC_KEY_MAX_SIZE 1024        // Maximum allowed KCM public key size

//
// Exports for vengcdll.dll (new OS DLL in VTL1)
//

// Attestation report generation API for user bound keys.
// Generates a session key, passes session key and provided challenge to EnclaveGetAttestationReport,
// encrypts the attestation report with EnclaveEncryptDataForTrustlet, returns the encrypted report.
HRESULT InitializeUserBoundKeySessionInfo(
    _In_reads_bytes_(challengeSize) const void* challenge,
    _In_ UINT32 challengeSize,
    _Outptr_result_buffer_(*reportSize) void** report,
    _Out_ UINT32* reportSize,
    _Out_ UINT_PTR* sessionKeyPtr
);

// Auth Context APIs
DECLARE_HANDLE(USER_BOUND_KEY_AUTH_CONTEXT_HANDLE);
DECLARE_HANDLE(USER_BOUND_KEY_SESSION_HANDLE);

HRESULT CloseUserBoundKeyAuthContextHandle(
    _In_ USER_BOUND_KEY_AUTH_CONTEXT_HANDLE handle);

// Session management APIs
// Creates a user bound key session handle from session key pointer and nonce
HRESULT CreateUserBoundKeySessionHandle(
    _In_ UINT_PTR sessionKeyPtr,
    _In_ ULONG64 sessionNonce,
    _Out_ USER_BOUND_KEY_SESSION_HANDLE* sessionHandle
);

// Gets session information from a session handle
HRESULT GetUserBoundKeySessionInfo(
    _In_ USER_BOUND_KEY_SESSION_HANDLE sessionHandle,
    _Out_ UINT_PTR* sessionKeyPtr,
    _Out_ ULONG64* sessionNonce
);

// Closes a user bound key session and destroys the associated BCRYPT_KEY_HANDLE
HRESULT CloseUserBoundKeySession(
    _In_ USER_BOUND_KEY_SESSION_HANDLE sessionHandle
);

/*
// Legacy structure for backward compatibility
typedef struct _KEY_CREDENTIAL_CACHE_CONFIG {
    UINT32 cacheType;
    UINT32 cacheTimeout; // in seconds
    UINT32 cacheCallCount;
} KEY_CREDENTIAL_CACHE_CONFIG;
*/

typedef enum _USER_BOUND_KEY_AUTH_CONTEXT_PROPERTIES {
    UserBoundKeyAuthContextPropertyCacheConfig = 0, // The cache configuration for the user bound key, encoded as a CACHE_CONFIG structure
} USER_BOUND_KEY_AUTH_CONTEXT_PROPERTIES;

// Called as part of the flow when creating a new user bound key.
// Decrypts the auth context blob provided by KCM and returns a handle to the decrypted blob
HRESULT GetUserBoundKeyAuthContext(
    _In_ UINT_PTR sessionKeyPtr,
    _In_reads_bytes_(authContextBlobSize) const void* authContextBlob, // auth context generated as part of RequestCreateAsync
    _In_ UINT32 authContextBlobSize,
    _Out_ USER_BOUND_KEY_AUTH_CONTEXT_HANDLE* authContextHandle
);

typedef struct _USER_BOUND_KEY_AUTH_CONTEXT_PROPERTY
{
    USER_BOUND_KEY_AUTH_CONTEXT_PROPERTIES name;
    UINT32 size;
    _Field_size_bytes_(size) void* value;
} USER_BOUND_KEY_AUTH_CONTEXT_PROPERTY;

// Verifies that the keyname matches the one in the auth context blob, 
// and validates cacheConfig, IsSecureIdOwnerId, publicKeyBytes
HRESULT ValidateUserBoundKeyAuthContext(
    _In_reads_bytes_(keyNameSize) const void* keyName,
    _In_ UINT32 keyNameSize,
    _In_ USER_BOUND_KEY_AUTH_CONTEXT_HANDLE authContextHandle,
    _In_ UINT32 count,
    _In_reads_(count) const USER_BOUND_KEY_AUTH_CONTEXT_PROPERTY* values
);

// Performs key establishment using the enclave key handle provided, along with the
// corresponding key from the KCM side (present in the auth context blob).
// Computes the key encryption key (KEK) for the user bound key.
// Encrypt the user key and produce material to save to disk
HRESULT ProtectUserBoundKey(
    _In_ USER_BOUND_KEY_AUTH_CONTEXT_HANDLE authContext,
    _In_reads_bytes_(userKeySize) const void* userKey,
    _In_ UINT32 userKeySize,
    _Outptr_result_buffer_(*boundKeySize) void** boundKey,
    _Inout_ UINT32* boundKeySize
);

// Creates an encrypted KCM request for DeriveSharedSecret using session information and ephemeral public key bytes
// NOTE OF CAUTION: We should prevent nonce reuse under any circumstances.
// This function handles nonce manipulation internally to prevent reuse.
HRESULT CreateEncryptedRequestForDeriveSharedSecret(
    _In_ USER_BOUND_KEY_SESSION_HANDLE sessionHandle,
    _In_reads_bytes_(keyNameSize) const void* keyName,
    _In_ UINT32 keyNameSize,
    _In_reads_bytes_(publicKeyBytesSize) const void* publicKeyBytes,
    _In_ UINT32 publicKeyBytesSize,
    _Outptr_result_buffer_(*encryptedRequestSize) void** encryptedRequest,
    _Out_ UINT32* encryptedRequestSize
);

// Decrypt the user key from material from disk
HRESULT UnprotectUserBoundKey(
    _In_ USER_BOUND_KEY_SESSION_HANDLE sessionHandle,
    _In_ USER_BOUND_KEY_AUTH_CONTEXT_HANDLE authContext,
    _In_reads_bytes_(sessionEncryptedDerivedSecretSize) const void* sessionEncryptedDerivedSecret,
    _In_ UINT32 sessionEncryptedDerivedSecretSize,
    _In_reads_bytes_(encryptedUserBoundKeySize) const void* encryptedUserBoundKey,
    _In_ UINT32 encryptedUserBoundKeySize,
    _Outptr_result_buffer_(*userKeySize) void** userKey,
    _Inout_ UINT32* userKeySize
);

#endif // VENGCDLL_H
