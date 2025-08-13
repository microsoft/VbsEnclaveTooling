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

// Forward declare DeveloperTypes to avoid circular dependency
namespace DeveloperTypes
{
struct keyCredentialCacheConfig;
}

// NGC Trustlet Identity constant
#ifndef TRUSTLETIDENTITY_NGC
#define TRUSTLETIDENTITY_NGC 6
#endif

// AES-GCM constants
#define AES_GCM_NONCE_SIZE 12
#define AES_GCM_TAG_SIZE 16

// Cryptographic constants
#define ECDH_P384_KEY_SIZE_BITS 384         // ECDH P-384 key size in bits
#define AES_256_KEY_SIZE_BYTES 32           // AES-256 session key size in bytes

// Buffer size constants
#define NGC_KEY_NAME_BUFFER_SIZE 256        // Buffer size for key names
#define NGC_ATTESTATION_BUFFER_SIZE 256     // Buffer size for attestation data

// NGC public key validation limits
#define NGC_PUBLIC_KEY_MIN_SIZE 32          // Minimum allowed NGC public key size
#define NGC_PUBLIC_KEY_MAX_SIZE 1024        // Maximum allowed NGC public key size

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

BOOL CloseUserBoundKeyAuthContextHandle(
    _In_ USER_BOUND_KEY_AUTH_CONTEXT_HANDLE handle);

// Legacy structure for backward compatibility
typedef struct _KEY_CREDENTIAL_CACHE_CONFIG {
    UINT32 cacheType;
    UINT32 cacheTimeout; // in seconds
    UINT32 cacheCallCount;
} KEY_CREDENTIAL_CACHE_CONFIG;

typedef enum _USER_BOUND_KEY_AUTH_CONTEXT_PROPERTIES {
    UserBoundKeyAuthContextPropertyCacheConfig = 0, // The cache configuration for the user bound key, encoded as a CACHE_CONFIG structure
} USER_BOUND_KEY_AUTH_CONTEXT_PROPERTIES;

// Called as part of the flow when creating a new user bound key.
// Decrypts the auth context blob provided by NGC and returns a handle to the decrypted blob
HRESULT GetUserBoundKeyCreationAuthContext(
    _In_ UINT_PTR sessionKeyPtr,
    _In_reads_bytes_(authContextBlobSize) const void* authContextBlob, // auth context generated as part of RequestCreateAsync
    _In_ UINT32 authContextBlobSize,
    _Out_ USER_BOUND_KEY_AUTH_CONTEXT_HANDLE* authContextHandle
);

// Called as part of the flow when loading an existing user bound key.
// Decrypts the auth context blob provided by NGC, verifies that the keyname matches the one in the auth context blob.
HRESULT GetUserBoundKeyLoadingAuthContext(
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
    _In_ PCWSTR keyName,
    _In_ USER_BOUND_KEY_AUTH_CONTEXT_HANDLE authContextHandle,
    _In_ UINT32 count,
    _In_reads_(count) const USER_BOUND_KEY_AUTH_CONTEXT_PROPERTY* values
);

// Performs key establishment using the enclave key handle provided, along with the
// corresponding key from the NGC side (present in the auth context blob).
// Computes the key encryption key (KEK) for the user bound key.
// Encrypt the user key and produce material to save to disk
HRESULT ProtectUserBoundKey(
    _In_ USER_BOUND_KEY_AUTH_CONTEXT_HANDLE authContext,
    _In_reads_bytes_(userKeySize) const void* userKey,
    _In_ UINT32 userKeySize,
    _Outptr_result_buffer_(*boundKeySize) void** boundKey,
    _Inout_ UINT32* boundKeySize
);

// Decrypt the user key from material from disk
HRESULT UnprotectUserBoundKey(
    _In_ USER_BOUND_KEY_AUTH_CONTEXT_HANDLE authContext,
    _In_reads_bytes_(secretSize) const void* secret,
    _In_ UINT32 secretSize,
    _In_reads_bytes_(boundKeySize) const void* boundKey,
    _In_ UINT32 boundKeySize,
    _Outptr_result_buffer_(*userKeySize) void** userKey,
    _Inout_ UINT32* userKeySize
);

#endif // VENGCDLL_H
