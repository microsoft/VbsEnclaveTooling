// Copyright (c) Microsoft Corporation.
//

#include "pch.h"
#include "..\veil_enclave_lib\vengcdll.h"
#include "vtl0_functions.vtl1.h"  // Add this include for debug_print
#include "wil_raw.h"
#include "memory.h"

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
#define KCM_KEY_NAME_MAX_LENGTH 256        // Buffer size for key names
#define KCM_ATTESTATION_BUFFER_SIZE 256     // Buffer size for attestation data

// KCM public key validation limits
#define KCM_PUBLIC_KEY_MIN_SIZE 32          // Minimum allowed KCM public key size
#define KCM_PUBLIC_KEY_MAX_SIZE 1024        // Maximum allowed KCM public key size

#define MAX_REQUEST_NONCE 100000            // Maximum allowed nonce value for request generation
#define MAX_ENCRYPTED_USER_KEY_SIZE 1024    // Maximum allowed encrypted user key size

// RAII types
using unique_bcrypt_key = wil_raw::unique_any<BCRYPT_KEY_HANDLE, decltype(&::BCryptDestroyKey), ::BCryptDestroyKey>;
using unique_bcrypt_secret = wil_raw::unique_any<BCRYPT_SECRET_HANDLE, decltype(&::BCryptDestroySecret), ::BCryptDestroySecret>;

struct KEY_CREDENTIAL_CACHE_CONFIG
{
    UINT32 cacheType;
    UINT32 cacheTimeout; // in seconds
    UINT32 cacheCallCount;
};

// Forward declarations for NGC types
// Structure to return values for NCRYPT_NGC_AUTHORIZATION_CONTEXT_PROPERTY
struct NCRYPT_NGC_AUTHORIZATION_CONTEXT
{
    // Disable constructor and copy constructor
    NCRYPT_NGC_AUTHORIZATION_CONTEXT() = delete;
    NCRYPT_NGC_AUTHORIZATION_CONTEXT(const NCRYPT_NGC_AUTHORIZATION_CONTEXT&) = delete;
    NCRYPT_NGC_AUTHORIZATION_CONTEXT& operator=(const NCRYPT_NGC_AUTHORIZATION_CONTEXT&) = delete;

    // Disable move constructor and move assignment
    NCRYPT_NGC_AUTHORIZATION_CONTEXT(NCRYPT_NGC_AUTHORIZATION_CONTEXT&&) = delete;
    NCRYPT_NGC_AUTHORIZATION_CONTEXT& operator=(NCRYPT_NGC_AUTHORIZATION_CONTEXT&&) = delete;

    // Destructor that zeroes out all bytes and the "trailing array"
    ~NCRYPT_NGC_AUTHORIZATION_CONTEXT()
    {
        // Zero-out the struct and the "trailing array"
        auto sizeToZero = sizeof(NCRYPT_NGC_AUTHORIZATION_CONTEXT) + publicKeyByteCount - sizeof(BYTE);
        RtlSecureZeroMemory(this, sizeToZero);
    }

    DWORD structSize;
    BOOL isSecureIdOwnerId;
    KEY_CREDENTIAL_CACHE_CONFIG cacheConfig;
    DWORD keyNameLength;
    WCHAR keyName[KCM_KEY_NAME_MAX_LENGTH];
    DWORD publicKeyByteCount;
    BYTE publicKey[1];
};

namespace AuthorizationContext
{
    //
    // Object table
    //
ObjectTable::Table<NCRYPT_NGC_AUTHORIZATION_CONTEXT> s_authContextTable;

static HRESULT ResolveObject(_In_ USER_BOUND_KEY_AUTH_CONTEXT_HANDLE publicHandle, _Out_ NCRYPT_NGC_AUTHORIZATION_CONTEXT** ppObject) noexcept
{
    if (!publicHandle || !ppObject)
    {
        return E_INVALIDARG;
    }

    auto handle = ObjectTable::Handle {reinterpret_cast<uintptr_t>(publicHandle)};
    auto* object = s_authContextTable.ResolveObject(handle);
    if (!object)
    {
        return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
    }

    *ppObject = object;
    return S_OK;
}

static HRESULT InsertObject(
    wil_raw::unique_ptr<NCRYPT_NGC_AUTHORIZATION_CONTEXT>&& object,
    _Out_ USER_BOUND_KEY_AUTH_CONTEXT_HANDLE* handle) noexcept
{
    ObjectTable::Handle tempHandle;
    RETURN_IF_FAILED(s_authContextTable.InsertObject(wil_raw::move(object), &tempHandle));
    *handle = reinterpret_cast<USER_BOUND_KEY_AUTH_CONTEXT_HANDLE>(tempHandle);
    //*handle = reinterpret_cast<USER_BOUND_KEY_AUTH_CONTEXT_HANDLE>(static_cast<uintptr_t>(tempHandle.value));
    return S_OK;
}

static HRESULT CloseHandle(_In_ USER_BOUND_KEY_AUTH_CONTEXT_HANDLE publicHandle) noexcept
{
    auto handle = ObjectTable::Handle {reinterpret_cast<uintptr_t>(publicHandle)};
    wil_raw::unique_ptr<NCRYPT_NGC_AUTHORIZATION_CONTEXT> object;
    RETURN_IF_FAILED(s_authContextTable.RemoveObject(handle, &object));
    object.reset();
    return S_OK;
}

// Allocate an NCRYPT_NGC_AUTHORIZATION_CONTEXT
static wil_raw::unique_ptr<NCRYPT_NGC_AUTHORIZATION_CONTEXT> Allocate(_In_ SIZE_T bufferSize)
{
    auto buffer = reinterpret_cast<NCRYPT_NGC_AUTHORIZATION_CONTEXT*>(VengcAlloc(bufferSize));
    if (buffer == nullptr)
    {
        return wil_raw::unique_ptr<NCRYPT_NGC_AUTHORIZATION_CONTEXT>{ nullptr };
    }

    wil_raw::unique_ptr<NCRYPT_NGC_AUTHORIZATION_CONTEXT> authContext {buffer};
    authContext->structSize = static_cast<DWORD>(bufferSize);
    return authContext;
}

// Validate integrity of auth context buffer
static HRESULT ValidateSerialData(
    _In_ const BYTE* buffer,
    _In_ SIZE_T bufferSize)
{
    if (bufferSize < sizeof(NCRYPT_NGC_AUTHORIZATION_CONTEXT))
    {
        return E_INVALIDARG;
    }

    auto context = reinterpret_cast<const NCRYPT_NGC_AUTHORIZATION_CONTEXT*>(buffer);

    // Validate the integrity of the decryptedAuthContext
    if (bufferSize < context->structSize)
    {
        return E_INVALIDARG;
    }

    // Verify the structure size field
    if (context->structSize != sizeof(NCRYPT_NGC_AUTHORIZATION_CONTEXT))
    {
        return E_INVALIDARG;
    }

    // Validate the trustlet data size is reasonable
    if (context->publicKeyByteCount < KCM_PUBLIC_KEY_MIN_SIZE || context->publicKeyByteCount > KCM_PUBLIC_KEY_MAX_SIZE)
    {
        return E_INVALIDARG;
    }

    // Verify the public key data doesn't exceed the buffer
    auto publicKeySize = bufferSize - offsetof(NCRYPT_NGC_AUTHORIZATION_CONTEXT, publicKey);
    if (context->publicKeyByteCount != publicKeySize)
    {
        return E_INVALIDARG;
    }

    constexpr UINT32 EXPECTED_NONCE_SIZE = 8;

    // The publicKey format is: [nonce (usually 16 bytes)][actual public key data]
    // For P-384, we expect the nonce to be 16 bytes followed by the public key in BCRYPT_ECCPUBLIC_BLOB format
    if (context->publicKeyByteCount <= EXPECTED_NONCE_SIZE)
    {
        return E_INVALIDARG;
    }

    // Verify the key name length is valid
    if (context->keyNameLength == 0 || (context->keyNameLength * sizeof(wchar_t)) > sizeof(context->keyName))
    {
        return E_INVALIDARG;
    }

    return S_OK;
}

// Deserialize buffer to NCRYPT_NGC_AUTHORIZATION_CONTEXT
static HRESULT Deserialize(
    _In_ const BYTE* buffer,
    _In_ SIZE_T bufferSize,
    _Out_ wil_raw::unique_ptr<NCRYPT_NGC_AUTHORIZATION_CONTEXT>* authContext)
{
    // Validate the data structure
    RETURN_IF_FAILED(ValidateSerialData(buffer, bufferSize));

    // Allocate the auth context
    auto tmpAuthContext = AuthorizationContext::Allocate(bufferSize);
    if (!tmpAuthContext)
    {
        return E_OUTOFMEMORY;
    }

    // Copy the data into the allocated structure
    memcpy(tmpAuthContext.get(), buffer, bufferSize);

    *authContext = wil_raw::move(tmpAuthContext);
    return S_OK;
}
}

namespace Vtl1MutualAuth
{
    // Header constants used throughout the namespace - defined once to eliminate duplication
static constexpr BYTE CHALLENGE_HEADER[10] = {'c','h','a','l','l','e','n','g','e','\0'};
static constexpr BYTE ATTESTATION_HEADER[8] = {'a','t','t','e','s','t','\0','\0'};
static constexpr SIZE_T c_challengeSize = 24;
static constexpr ULONG64 c_maxRequestNonce = 100000;  // Maximum allowed nonce value for request generation
static constexpr UINT32 c_maxEncryptedUserKeySize = 1024;  // Maximum allowed encrypted user key size

struct SessionChallenge
{
    static constexpr SIZE_T c_sessionChallengeVectorSize = sizeof(CHALLENGE_HEADER) + c_challengeSize + sizeof(PS_TRUSTLET_TKSESSION_ID);
    BYTE challenge[c_challengeSize];
    PS_TRUSTLET_TKSESSION_ID sessionId;

    HRESULT ToVector(_Out_writes_bytes_(c_sessionChallengeVectorSize) BYTE* buffer) const
    {
        if (buffer == NULL)
        {
            return E_INVALIDARG;
        }

        SIZE_T index = 0;

        memcpy(buffer + index, CHALLENGE_HEADER, sizeof(CHALLENGE_HEADER));
        index += sizeof(CHALLENGE_HEADER);

        memcpy(buffer + index, challenge, c_challengeSize);
        index += c_challengeSize;

        memcpy(buffer + index, &sessionId, sizeof(sessionId));
        index += sizeof(sessionId);

        return S_OK;
    }

    static HRESULT FromVector(const BYTE* buffer, UINT32 bufferSize, _Out_ SessionChallenge* result)
    {
        if (buffer == NULL || result == NULL)
        {
            return E_INVALIDARG;
        }

        SIZE_T expectedSize = sizeof(CHALLENGE_HEADER) + c_challengeSize + sizeof(result->sessionId);
        if (bufferSize < expectedSize)
        {
            return NTE_BAD_DATA;
        }

        SIZE_T index = 0;

        // Check if buffer starts with the expected challenge header
        if (0 != memcmp(CHALLENGE_HEADER, buffer, sizeof(CHALLENGE_HEADER)))
        {
            return NTE_BAD_TYPE;
        }
        index += sizeof(CHALLENGE_HEADER);

        // Copy challenge data
        memcpy(result->challenge, buffer + index, c_challengeSize);
        index += c_challengeSize;

        // Copy session ID
        memcpy(&result->sessionId, buffer + index, sizeof(result->sessionId));
        index += sizeof(result->sessionId);

        return S_OK;
    }
};

struct AttestationData
{
    static constexpr SIZE_T c_symmetricSecretSize = 32;
    static constexpr SIZE_T c_attestationDataVectorSize = sizeof(ATTESTATION_HEADER) + c_challengeSize + c_symmetricSecretSize;
    BYTE challenge[c_challengeSize];
    BYTE symmetricSecret[c_symmetricSecretSize];

    HRESULT ToVector(_Out_writes_bytes_(c_attestationDataVectorSize) BYTE* buffer) const
    {
        if (buffer == NULL)
        {
            return E_INVALIDARG;
        }

        SIZE_T index = 0;

        memcpy(buffer + index, ATTESTATION_HEADER, sizeof(ATTESTATION_HEADER));
        index += sizeof(ATTESTATION_HEADER);

        memcpy(buffer + index, challenge, c_challengeSize);
        index += c_challengeSize;

        memcpy(buffer + index, symmetricSecret, c_symmetricSecretSize);
        index += c_symmetricSecretSize;

        return S_OK;
    }

    static HRESULT FromVector(const BYTE* buffer, UINT32 bufferSize, _Out_ AttestationData* result)
    {
        if (buffer == NULL || result == NULL)
        {
            return E_INVALIDARG;
        }

        SIZE_T expectedSize = sizeof(ATTESTATION_HEADER) + c_challengeSize + c_symmetricSecretSize;
        if (bufferSize < expectedSize)
        {
            return NTE_BAD_DATA;
        }

        SIZE_T index = 0;

        // Check if buffer starts with the expected attestation header
        if (0 != memcmp(ATTESTATION_HEADER, buffer, sizeof(ATTESTATION_HEADER)))
        {
            return NTE_BAD_TYPE;
        }
        index += sizeof(ATTESTATION_HEADER);

        // Copy challenge data
        memcpy(result->challenge, buffer + index, c_challengeSize);
        index += c_challengeSize;

        // Copy symmetric secret
        memcpy(result->symmetricSecret, buffer + index, c_symmetricSecretSize);
        index += c_symmetricSecretSize;

        return S_OK;
    }
};
}

// Internal structure to hold session information (moved from header)
struct USER_BOUND_KEY_SESSION_INTERNAL
{
    unique_bcrypt_key sessionKey {};
    volatile LONG64 sessionNonce {};
};

namespace SessionInfo
{
    //
    // Object table
    //
ObjectTable::Table<USER_BOUND_KEY_SESSION_INTERNAL> s_sessionTable;

static HRESULT ResolveObject(_In_ USER_BOUND_KEY_SESSION_HANDLE publicHandle, _Out_ USER_BOUND_KEY_SESSION_INTERNAL** ppObject) noexcept
{
    if (!publicHandle || !ppObject)
    {
        return E_INVALIDARG;
    }

    auto handle = ObjectTable::Handle {reinterpret_cast<uintptr_t>(publicHandle)};
    auto* object = s_sessionTable.ResolveObject(handle);
    if (!object)
    {
        return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
    }

    *ppObject = object;
    return S_OK;
}

static HRESULT InsertObject(
    wil_raw::unique_ptr<USER_BOUND_KEY_SESSION_INTERNAL>&& object,
    _Out_ USER_BOUND_KEY_SESSION_HANDLE* handle) noexcept
{
    ObjectTable::Handle tempHandle;
    RETURN_IF_FAILED(s_sessionTable.InsertObject(wil_raw::move(object), &tempHandle));
    *handle = reinterpret_cast<USER_BOUND_KEY_SESSION_HANDLE>(tempHandle);
    // *handle = reinterpret_cast<USER_BOUND_KEY_SESSION_HANDLE>(static_cast<uintptr_t>(tempHandle.value));
    return S_OK;
}

static HRESULT CloseHandle(_In_ USER_BOUND_KEY_SESSION_HANDLE publicHandle) noexcept
{
    auto handle = ObjectTable::Handle {reinterpret_cast<uintptr_t>(publicHandle)};
    wil_raw::unique_ptr<USER_BOUND_KEY_SESSION_INTERNAL> object;
    RETURN_IF_FAILED(s_sessionTable.RemoveObject(handle, &object));
    object.reset();
    return S_OK;
}

// Make a session info object
static wil_raw::unique_ptr<USER_BOUND_KEY_SESSION_INTERNAL> Create(unique_bcrypt_key&& sessionKey)
{
    auto buffer = reinterpret_cast<USER_BOUND_KEY_SESSION_INTERNAL*>(VengcAlloc(sizeof(USER_BOUND_KEY_SESSION_INTERNAL)));
    if (!buffer)
    {
        return wil_raw::unique_ptr<USER_BOUND_KEY_SESSION_INTERNAL>{ nullptr };
    }

    auto sessionInfo = wil_raw::unique_ptr<USER_BOUND_KEY_SESSION_INTERNAL>(buffer);
    sessionInfo->sessionKey = wil_raw::move(sessionKey);

    return sessionInfo;
}

static LONG64 ConsumeNextSessionNonce(_In_ USER_BOUND_KEY_SESSION_INTERNAL* sessionInfo)
{
    return InterlockedIncrement64(&sessionInfo->sessionNonce);
}
}

static int CompareNullTerminatedWideStrings(const wchar_t* s1, const wchar_t* s2)
{
    while (*s1 && *s2 && (*s1 == *s2))
    {
        ++s1;
        ++s2;
    }
    return static_cast<int>(*s1) - static_cast<int>(*s2);
}

//
// Private helper functions for InitializeUserBoundKeySession
//

//
// Step 2: Generate session key for encryption
//
static HRESULT
GenerateSessionKey(
    _In_ UINT32 sessionKeySize,
    _Out_ BCRYPT_KEY_HANDLE* phSessionKey,
    _Out_ unique_secure_blob* pSessionKeyBytes
)
{
    // Allocate secure memory for key bytes using RAII
    auto sessionKeyBytes = make_unique_secure_blob(sessionKeySize);
    if (!sessionKeyBytes) 
    {
        return E_OUTOFMEMORY;
    }

    // Generate cryptographically secure random key bytes
    RETURN_IF_FAILED(HRESULT_FROM_NT(BCryptGenRandom(NULL, sessionKeyBytes.get(), sessionKeySize, BCRYPT_USE_SYSTEM_PREFERRED_RNG)));

    // Create symmetric key from the generated bytes using AES-GCM algorithm
    unique_bcrypt_key hSessionKey;
    RETURN_IF_FAILED(HRESULT_FROM_NT(BCryptGenerateSymmetricKey(BCRYPT_AES_GCM_ALG_HANDLE, &hSessionKey, NULL, 0, sessionKeyBytes.get(), sessionKeySize, 0)));

    *phSessionKey = hSessionKey.release();
    *pSessionKeyBytes = wil_raw::move(sessionKeyBytes);

    return S_OK;
}

//
// Step 3: Generate attestation report with session key and challenge
//
static HRESULT
GenerateAttestationReport(
    _In_ const BYTE* challenge,
    _In_ UINT32 challengeSize,
    _In_ BYTE* pSessionKeyBytes,
    _In_ UINT32 sessionKeySize,
    _Out_ unique_secure_blob* pAttestationReport,
    _Out_ PS_TRUSTLET_TKSESSION_ID* pSessionId
)
{
    // Parse the NGC session challenge using SessionChallenge directly
    Vtl1MutualAuth::SessionChallenge sessionChallenge {};
    RETURN_IF_FAILED(Vtl1MutualAuth::SessionChallenge::FromVector(challenge, challengeSize, &sessionChallenge));

    // Create AttestationData using the standard Vtl1MutualAuthNoStd structure
    // Copy challenge bytes (guaranteed to be exactly 24 bytes)
    Vtl1MutualAuth::AttestationData attestationData {};
    memcpy(attestationData.challenge, sessionChallenge.challenge, sizeof(attestationData.challenge));

    // Copy session key as symmetric secret (both are 32 bytes)
    // static_assert(sizeof(attestationData.symmetricSecret) == sessionKeySize, "Session key size mismatch");
    memcpy(attestationData.symmetricSecret, pSessionKeyBytes, sessionKeySize);

    // Convert to vector for enclave data
    BYTE attestationVector[Vtl1MutualAuth::AttestationData::c_attestationDataVectorSize];
    RETURN_IF_FAILED(attestationData.ToVector(attestationVector));

    // Prepare enclaveData buffer
    static_assert(Vtl1MutualAuth::AttestationData::c_attestationDataVectorSize <= ENCLAVE_REPORT_DATA_LENGTH);
    BYTE enclaveData[ENCLAVE_REPORT_DATA_LENGTH] = {0};
    memcpy(enclaveData, attestationVector, Vtl1MutualAuth::AttestationData::c_attestationDataVectorSize);

    // Call Windows enclave attestation API to get size
    UINT32 attestationReportSize = 0;
    RETURN_IF_FAILED(EnclaveGetAttestationReport(enclaveData, NULL, 0, &attestationReportSize));

    // Allocate secure buffer for the actual attestation report using RAII
    auto attestationReport = make_unique_secure_blob(attestationReportSize);
    if (!attestationReport)
    {
        return E_OUTOFMEMORY;
    }

    // Get the actual attestation report
    RETURN_IF_FAILED(EnclaveGetAttestationReport(enclaveData, attestationReport.get(), attestationReportSize, &attestationReportSize));

    *pAttestationReport = wil_raw::move(attestationReport);
    *pSessionId = sessionChallenge.sessionId;

    return S_OK;
}

//
// Step 4: Encrypt attestation report using EnclaveEncryptDataForTrustlet
//
static HRESULT
EncryptAttestationReport(
    _In_ void* pAttestationReport,
    _In_ UINT32 attestationReportSize,
    _In_ PS_TRUSTLET_TKSESSION_ID sessionId,
    _Out_ unique_secure_blob* pEncryptedReport
)
{
    // Set up trustlet binding data
    TRUSTLET_BINDING_DATA trustletData;
    trustletData.TrustletIdentity = TRUSTLETIDENTITY_KCM;
    trustletData.TrustletSessionId = sessionId;
    trustletData.TrustletSvn = 0;
    trustletData.Reserved1 = 0;
    trustletData.Reserved2 = 0;

    // Get the required buffer size for encrypted data
    UINT32 tempEncryptedSize = 0;
    RETURN_IF_FAILED(EnclaveEncryptDataForTrustlet(
        pAttestationReport,
        attestationReportSize,
        &trustletData,
        NULL,
        0,
        &tempEncryptedSize
    ));

    // Allocate secure buffer for encrypted report using RAII
    auto encryptedReport = make_unique_secure_blob(tempEncryptedSize);
    if (!encryptedReport)
    {
        return E_OUTOFMEMORY;
    }

    // Perform the actual encryption
    RETURN_IF_FAILED(EnclaveEncryptDataForTrustlet(
        pAttestationReport,
        attestationReportSize,
        &trustletData,
        encryptedReport.get(),
        encryptedReport.size(),
        &tempEncryptedSize
    ));

    if (tempEncryptedSize != encryptedReport.size())
    {
        return E_UNEXPECTED;
    }

    *pEncryptedReport = wil_raw::move(encryptedReport);

    return S_OK;
}

//
// Session management APIs
//

// Closes a user bound key session and destroys the associated BCRYPT_KEY_HANDLE
HRESULT CloseUserBoundKeySession(_In_ USER_BOUND_KEY_SESSION_HANDLE sessionHandle)
{
    SessionInfo::CloseHandle(sessionHandle);
    return S_OK;
}


// Attestation report generation API for user bound keys.
// Generates a session key, passes session key and provided challenge to EnclaveGetAttestationReport,
// encrypts the attestation report with EnclaveEncryptDataForTrustlet, returns the encrypted report. 
HRESULT InitializeUserBoundKeySession(
    _In_reads_bytes_(challengeSize) const void* challenge,
    _In_ UINT32 challengeSize,
    _Outptr_result_buffer_(*reportSize) void** report,
    _Out_ UINT32* reportSize,
    _Out_ USER_BOUND_KEY_SESSION_HANDLE* sessionHandle
)
{
    const UINT32 SESSION_KEY_SIZE = AES_256_KEY_SIZE_BYTES; // 256-bit AES key
    PS_TRUSTLET_TKSESSION_ID sessionId = {0};

    //
    // Step 1: Validate input parameters
    //
    if (!challenge || challengeSize == 0 || !report || !reportSize || !sessionHandle)
    {
        return E_POINTER;
    }

    //
    // Step 2: Generate session key for encryption
    //
    unique_bcrypt_key sessionKey;
    unique_secure_blob sessionKeyBytes;
    RETURN_IF_FAILED(GenerateSessionKey(SESSION_KEY_SIZE, &sessionKey, &sessionKeyBytes));

    //
    // Step 3: Generate attestation report with session key and challenge
    //
    unique_secure_blob attestationReport;
    RETURN_IF_FAILED(GenerateAttestationReport(reinterpret_cast<const BYTE*>(challenge), challengeSize, sessionKeyBytes.get(), SESSION_KEY_SIZE,
        &attestationReport, &sessionId));

//
// Step 4: Encrypt attestation report using EnclaveEncryptDataForTrustlet
//
    unique_secure_blob encryptedReport;
    RETURN_IF_FAILED(EncryptAttestationReport(attestationReport.get(), attestationReport.size(), sessionId, &encryptedReport));

    //
    // Step 5: Create session
    //
    auto sessionInfo = SessionInfo::Create(wil_raw::move(sessionKey));
    if (!sessionInfo)
    {
        return E_OUTOFMEMORY;
    }

    // Store in object table
    USER_BOUND_KEY_SESSION_HANDLE tmpSessionHandle;
    RETURN_IF_FAILED(SessionInfo::InsertObject(wil_raw::move(sessionInfo), &tmpSessionHandle));

    *report = encryptedReport.release();
    *reportSize = encryptedReport.size();
    *sessionHandle = tmpSessionHandle;

    return S_OK;
}

HRESULT CloseUserBoundKeyAuthContext(
    _In_ USER_BOUND_KEY_AUTH_CONTEXT_HANDLE handle)
{
    AuthorizationContext::CloseHandle(handle);
    return S_OK;
}

//
// Private helper functions for GetUserBoundKeyAuthContext
//

//
// Step 2: Decrypt the auth context blob using BCrypt APIs
//
static HRESULT
DecryptAuthContextBlob(
    _In_ BCRYPT_KEY_HANDLE sessionKey,
    _In_ ULONG64 localNonce,
    _In_ const BYTE* authContextBlob,
    _In_ UINT32 authContextBlobSize,
    _Out_ wil_raw::unique_ptr<NCRYPT_NGC_AUTHORIZATION_CONTEXT>* authContext
)
{
    constexpr UINT32 VTL1_TAG_SIZE = AES_GCM_TAG_SIZE;       // AES-GCM auth tag at end
    constexpr ULONG64 c_responderBitFlip = 0x80000000ULL;

    // The auth context blob was encrypted using ClientAuth::EncryptResponse which uses
    // VTL1 mutual authentication protocol with AES-GCM format.
    // IMPORTANT: EncryptResponse (new protocol) format is: [encrypted data][16-byte auth tag]
    // The nonce is NOT stored in the encrypted blob - it must be provided separately!

    // For EncryptResponse format: [encrypted data][16-byte auth tag]
    if (authContextBlobSize < VTL1_TAG_SIZE)
    {
        return NTE_BAD_DATA;
    }

    // For EncryptResponse, we need to reconstruct the nonce used during encryption
    // The nonce used was: requestNonce ^ c_responderBitFlip (where requestNonce was provided to EncryptResponse)
    UINT64 nonce = localNonce ^ c_responderBitFlip;  // Apply responder bit flip as per VTL1 protocol

    // Add nonce value towards the end of the buffer (last 8 bytes)
    BYTE nonceBuffer[AES_GCM_NONCE_SIZE] = {0}; // Fill with 0s
    memcpy(&nonceBuffer[AES_GCM_NONCE_SIZE - sizeof(nonce)], &nonce, sizeof(nonce));

    // Extract components from the EncryptResponse encrypted blob
    // Format: [encrypted data][16-byte auth tag] - NO NONCE stored in blob
    BYTE* pEncryptedData = const_cast<BYTE*>(authContextBlob);
    UINT32 encryptedDataSize = authContextBlobSize - VTL1_TAG_SIZE;
    BYTE* pAuthTag = pEncryptedData + encryptedDataSize;

    // Set up AES-GCM authentication info for VTL1 format
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = nonceBuffer;
    authInfo.cbNonce = AES_GCM_NONCE_SIZE;
    authInfo.pbTag = reinterpret_cast<PUCHAR>(pAuthTag);
    authInfo.cbTag = VTL1_TAG_SIZE;

    // Allocate secure buffer for decrypted data using RAII
    auto decryptedBlob = make_unique_secure_blob(encryptedDataSize);
    if (!decryptedBlob)
    {
        return E_OUTOFMEMORY;
    }

    // Perform AES-GCM decryption using VTL1 format
    ULONG bytesDecrypted = 0;
    RETURN_IF_FAILED(HRESULT_FROM_NT(BCryptDecrypt(
        sessionKey,
        reinterpret_cast<PUCHAR>(pEncryptedData),
        encryptedDataSize,
        &authInfo,
        NULL,  // No IV for GCM (nonce is in authInfo)
        0,
        decryptedBlob.get(),
        decryptedBlob.size(),
        &bytesDecrypted,
        0
    )));

    if (bytesDecrypted != decryptedBlob.size())
    {
        return E_UNEXPECTED;
    }

    // Allocate an NCRYPT_NGC_AUTHORIZATION_CONTEXT and copy the decrypted data into it
    RETURN_IF_FAILED(AuthorizationContext::Deserialize(decryptedBlob.get(), decryptedBlob.size(), authContext));
    return S_OK;
}

// Called as part of the flow when creating/loading a new user bound key.
// Decrypts the auth context blob provided by NGC and returns a handle to the decrypted blob
HRESULT GetUserBoundKeyAuthContext(
    _In_ USER_BOUND_KEY_SESSION_HANDLE sessionHandle,
    _In_reads_bytes_(authContextBlobSize) const void* authContextBlob,
    _In_ UINT32 authContextBlobSize,
    _In_ UINT64 localNonce,
    _Out_ USER_BOUND_KEY_AUTH_CONTEXT_HANDLE* authContextHandle
)
{
    if (!authContextBlob || authContextBlobSize == 0 || !authContextHandle)
    {
        return E_INVALIDARG;
    }

    USER_BOUND_KEY_SESSION_INTERNAL* sessionInfo;
    RETURN_IF_FAILED(SessionInfo::ResolveObject(sessionHandle, &sessionInfo));

    // Decrypt the auth context blob using BCrypt APIs
    wil_raw::unique_ptr<NCRYPT_NGC_AUTHORIZATION_CONTEXT> decryptedAuthContext {};
    RETURN_IF_FAILED(DecryptAuthContextBlob(sessionInfo->sessionKey.get(), localNonce, reinterpret_cast<const BYTE*>(authContextBlob), authContextBlobSize, & decryptedAuthContext));

    // Store in object table and return handle
    RETURN_IF_FAILED(AuthorizationContext::InsertObject(wil_raw::move(decryptedAuthContext), authContextHandle));
    return S_OK;
}

//
// Private helper functions for ValidateUserBoundKeyAuthContext
//
//
// Step 2: Verify keyName, isSecureIdOwnerId and cacheConfig
//
static HRESULT
ValidateAuthorizationContext(
    _In_ PCWSTR keyName,
    _In_ NCRYPT_NGC_AUTHORIZATION_CONTEXT* authCtx,
    _In_ UINT32 count,
    _In_ const USER_BOUND_KEY_AUTH_CONTEXT_PROPERTY* authctxproperties
)
{
    // Compare the extracted key name with the provided key name
    if (CompareNullTerminatedWideStrings(keyName, authCtx->keyName) != 0)
    {
        // Key names don't match - this auth context is for a different key
        return E_ACCESSDENIED;
    }

    // Always verify the secure id is owner id state
    if (!authCtx->isSecureIdOwnerId)
    {
        // This authorization context is not for the secure ID owner
        return E_ACCESSDENIED;
    }

    // Loop through all provided properties and validate each one
    for (UINT32 i = 0; i < count; i++)
    {
        const auto& currentProperty = authctxproperties[i];

        switch (currentProperty.name)
        {
            case UserBoundKeyAuthContextPropertyCacheConfig:
            {
                // Verify cache_config for authCtx == the one from caller
                if (currentProperty.size != sizeof(KEY_CREDENTIAL_CACHE_CONFIG) || currentProperty.value == NULL)
                {
                    return E_INVALIDARG;
                }

                auto callerCacheConfig = reinterpret_cast<KEY_CREDENTIAL_CACHE_CONFIG*>(currentProperty.value);
                if (authCtx->cacheConfig.cacheType != callerCacheConfig->cacheType)
                {
                    return E_INVALIDARG;
                }
                break;
            }

            default:
            {
                // Unknown property type
                return E_INVALIDARG;
            }
        }
    }

    return S_OK;
}

// Verifies that the keyname matches the one in the auth context blob, 
// and validates cacheConfig, IsSecureIdOwnerId, publicKeyBytes
HRESULT ValidateUserBoundKeyAuthContext(
    _In_ PCWSTR keyName,
    _In_ USER_BOUND_KEY_AUTH_CONTEXT_HANDLE authContextHandle,
    _In_ UINT32 count,
    _In_reads_(count) const USER_BOUND_KEY_AUTH_CONTEXT_PROPERTY* values
)
{
    // Validate input parameters
    if (!keyName || authContextHandle == NULL || (count > 0 && !values))
    {
        return E_INVALIDARG;
    }

    NCRYPT_NGC_AUTHORIZATION_CONTEXT* authContext;
    RETURN_IF_FAILED(AuthorizationContext::ResolveObject(authContextHandle, &authContext));

    // Verify properties against authorization context
    return ValidateAuthorizationContext(keyName, authContext, count, values);
}

//
// Private helper functions for ProtectUserBoundKey
//
//
// Step 2: Extract NGC public key and perform key establishment
//
static HRESULT
PerformECDHKeyEstablishment(
    _In_ NCRYPT_NGC_AUTHORIZATION_CONTEXT* authCtx,
    _Out_ BCRYPT_KEY_HANDLE* pEcdhKeyPair,
    _Out_ BCRYPT_KEY_HANDLE* pHelloPublicKeyHandle,
    _Out_ BCRYPT_SECRET_HANDLE* pEcdhSecret,
    _Out_ unique_secure_blob* sharedSecret
)
{
    // Skip the nonce to get to the actual public key data
    constexpr UINT32 EXPECTED_NONCE_SIZE = 8;
    BYTE* pNgcPublicKeyData = authCtx->publicKey + EXPECTED_NONCE_SIZE;
    UINT32 ngcPublicKeySize = authCtx->publicKeyByteCount - EXPECTED_NONCE_SIZE;

    // Import NGC public key for ECDH
    // The public key data (after skipping header) should be in BCRYPT_ECCPUBLIC_BLOB format
    unique_bcrypt_key helloPublicKeyHandle;
    RETURN_IF_FAILED(HRESULT_FROM_NT(BCryptImportKeyPair(
        BCRYPT_ECDH_P384_ALG_HANDLE,
        NULL,
        BCRYPT_ECCPUBLIC_BLOB,
        &helloPublicKeyHandle,
        pNgcPublicKeyData,
        ngcPublicKeySize,
        0)));

    // Generate enclave key pair for ECDH (384-bit for P-384)
    unique_bcrypt_key ecdhKeyPair;
    RETURN_IF_FAILED(HRESULT_FROM_NT(BCryptGenerateKeyPair(BCRYPT_ECDH_P384_ALG_HANDLE, &ecdhKeyPair, ECDH_P384_KEY_SIZE_BITS, 0)));

    // Finalize the enclave key pair
    RETURN_IF_FAILED(HRESULT_FROM_NT(BCryptFinalizeKeyPair(ecdhKeyPair.get(), 0)));

    // Derive a key to use as a Key-Encryption-Key (KEK)
    // Perform ECDH secret agreement
    unique_bcrypt_secret ecdhSecret;
    RETURN_IF_FAILED(HRESULT_FROM_NT(BCryptSecretAgreement(ecdhKeyPair.get(), helloPublicKeyHandle.get(), &ecdhSecret, 0)));

    // Derive the shared secret
    ULONG derivedKeySize = 0;
    RETURN_IF_FAILED(HRESULT_FROM_NT(BCryptDeriveKey(ecdhSecret.get(), BCRYPT_KDF_RAW_SECRET, NULL, NULL, 0, &derivedKeySize, 0)));

    // Allocate secure buffer for the actual shared secret using RAII
    auto tmpSharedSecret = make_unique_secure_blob(derivedKeySize);

    if (!tmpSharedSecret)
    {
        return E_OUTOFMEMORY;
    }

    // Actually derive the shared secret into the buffer
    RETURN_IF_FAILED(HRESULT_FROM_NT(BCryptDeriveKey(ecdhSecret.get(), BCRYPT_KDF_RAW_SECRET, NULL, tmpSharedSecret.get(), derivedKeySize, &derivedKeySize, 0)));

    *pEcdhKeyPair = ecdhKeyPair.release();
    *pHelloPublicKeyHandle = helloPublicKeyHandle.release();
    *pEcdhSecret = ecdhSecret.release();
    *sharedSecret = wil_raw::move(tmpSharedSecret);

    return S_OK;
}

///
// Step 3: Compute KEK from the established shared secret
//
static HRESULT
ComputeKEKFromSharedSecret(
    _In_ BCRYPT_KEY_HANDLE ecdhKeyPair,
    _In_ BYTE* pSharedSecret,
    _In_ ULONG derivedKeySize,
    _Out_ BCRYPT_KEY_HANDLE* phDerivedKey,
    _Out_ unique_sized_blob* enclavePublicKeyBlob
)
{
    unique_bcrypt_key hDerivedKey;
    ULONG enclavePublicKeyBlobSize = 0;

    // Generate symmetric key from the shared secret for KEK derivation
    RETURN_IF_FAILED(HRESULT_FROM_NT(BCryptGenerateSymmetricKey(
        BCRYPT_AES_GCM_ALG_HANDLE,// Algorithm handle (reuse ECC algorithm handle)
        &hDerivedKey,               // Output key handle
        NULL,                       // Key object buffer (auto-allocated)
        0,                          // Key object buffer size
        pSharedSecret,              // Key material (shared secret)
        derivedKeySize,             // Key material size
        0)));                        // Flags

    // Export enclave public key for later use
    RETURN_IF_FAILED(HRESULT_FROM_NT(BCryptExportKey(
        ecdhKeyPair,
        NULL,
        BCRYPT_ECCPUBLIC_BLOB,
        NULL,
        0,
        &enclavePublicKeyBlobSize,
        0)));

    auto enclavePublicKeyBytes = make_unique_sized_blob(enclavePublicKeyBlobSize);
    if (!enclavePublicKeyBytes)
    {
        return E_OUTOFMEMORY;
    }

    RETURN_IF_FAILED(HRESULT_FROM_NT(BCryptExportKey(
        ecdhKeyPair,
        NULL,
        BCRYPT_ECCPUBLIC_BLOB,
        enclavePublicKeyBytes.get(),
        enclavePublicKeyBytes.size(),
        &enclavePublicKeyBlobSize,
        0)));

    *phDerivedKey = hDerivedKey.release();
    *enclavePublicKeyBlob = wil_raw::move(enclavePublicKeyBytes);

    return S_OK;
}

//
// Step 4.1: Create bound key structure from encrypted components
//
static HRESULT
CreateBoundKeyStructure(
    _In_ BYTE* pEnclavePublicKeyBlob,
    _In_ ULONG enclavePublicKeyBlobSize,
    _In_ BYTE* nonce,
    _In_ BYTE* pEncryptedUserKey,
    _In_ ULONG bytesEncrypted,
    _In_ BYTE* authTag,
    _Out_ unique_sized_blob* boundKeyMaterial
)
{
    // Create the bound key structure:
    // [enclave public key blob size (4 bytes)]
    // [enclave public key blob]
    // [nonce (12 bytes)]
    // [encrypted user key size (4 bytes)]
    // [encrypted user key data]
    // [authentication tag (16 bytes)]

    UINT32 actualBoundKeySize = sizeof(UINT32) + enclavePublicKeyBlobSize +
        AES_GCM_NONCE_SIZE + sizeof(UINT32) +
        bytesEncrypted + AES_GCM_TAG_SIZE;

    auto tmpBoundKeyMaterial = make_unique_sized_blob(actualBoundKeySize);
    if (!tmpBoundKeyMaterial)
    {
        return E_OUTOFMEMORY;
    }

    BYTE* pCurrentPos = static_cast<BYTE*>(tmpBoundKeyMaterial.get());

    // Store enclave public key blob size
    *reinterpret_cast<UINT32*>(pCurrentPos) = enclavePublicKeyBlobSize;
    pCurrentPos += sizeof(UINT32);

    // Store enclave public key blob
    memcpy(pCurrentPos, pEnclavePublicKeyBlob, enclavePublicKeyBlobSize);
    pCurrentPos += enclavePublicKeyBlobSize;

    // Store nonce
    memcpy(pCurrentPos, nonce, AES_GCM_NONCE_SIZE);
    pCurrentPos += AES_GCM_NONCE_SIZE;

    // Store encrypted user key size
    *reinterpret_cast<UINT32*>(pCurrentPos) = bytesEncrypted;
    pCurrentPos += sizeof(UINT32);

    // Store encrypted user key data
    memcpy(pCurrentPos, pEncryptedUserKey, bytesEncrypted);
    pCurrentPos += bytesEncrypted;

    // Store authentication tag
    memcpy(pCurrentPos, authTag, AES_GCM_TAG_SIZE);

    *boundKeyMaterial = wil_raw::move(tmpBoundKeyMaterial);

    return S_OK;
}

//
// Step 4: Encrypt user key using the KEK with AES-GCM
//
static HRESULT
EncryptUserKeyWithKEK(
    _In_ BCRYPT_KEY_HANDLE hDerivedKey,
    _In_ const BYTE* userKey,
    _In_ UINT32 userKeySize,
    _In_ BYTE* enclavePublicKeyBlob,
    _In_ ULONG enclavePublicKeyBlobSize,
    _Out_ unique_sized_blob* boundKey
)
{
    // Generate nonce using BCryptGenRandom
    BYTE nonce[AES_GCM_NONCE_SIZE];
    RETURN_IF_FAILED(HRESULT_FROM_NT(BCryptGenRandom(NULL, nonce, AES_GCM_NONCE_SIZE, BCRYPT_USE_SYSTEM_PREFERRED_RNG)));

    // Set up AES-GCM authentication info
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = nonce;
    authInfo.cbNonce = AES_GCM_NONCE_SIZE;
    authInfo.cbTag = AES_GCM_TAG_SIZE;

    // Allocate secure buffer for encrypted user key using RAII
    UINT32 encryptedUserKeySize = userKeySize;
    auto encryptedUserKey = make_unique_secure_blob(encryptedUserKeySize);
    if (!encryptedUserKey)
    {
        return E_OUTOFMEMORY;
    }

    BYTE authTag[AES_GCM_TAG_SIZE];
    authInfo.pbTag = authTag;

    // Call BCryptEncrypt on the userKey using hDerivedKey
    ULONG bytesEncrypted = 0;
    RETURN_IF_FAILED(HRESULT_FROM_NT(BCryptEncrypt(
        hDerivedKey,
        reinterpret_cast<PUCHAR>(const_cast<BYTE*>(userKey)),
        userKeySize,
        &authInfo,
        NULL,  // No IV for GCM (nonce is in authInfo)
        0,
        encryptedUserKey.get(),
        encryptedUserKey.size(),
        &bytesEncrypted,
        0
    )));

    if (bytesEncrypted != encryptedUserKey.size())
    {
        return E_UNEXPECTED;
    }

    // Create bound key structure from encrypted components
    return CreateBoundKeyStructure(
        enclavePublicKeyBlob,
        enclavePublicKeyBlobSize,
        nonce,
        encryptedUserKey.get(),
        encryptedUserKey.size(),
        authTag,
        boundKey
    );
}

// Performs key establishment using the enclave key handle provided, along with the
// corresponding key from the NGC side (present in the auth context blob).
// Computes the key encryption key (KEK) for the user bound key.
// Encrypt the user key and produce material to save to disk
HRESULT ProtectUserBoundKey(
    _In_ USER_BOUND_KEY_AUTH_CONTEXT_HANDLE authContextHandle,
    _In_reads_bytes_(userKeySize) const void* userKeyBlob,
    _In_ UINT32 userKeySize,
    _Outptr_result_buffer_(*boundKeySize) void** boundKey,
    _Inout_ UINT32* boundKeySize
)
{
    const BYTE* userKey = reinterpret_cast<const BYTE*>(userKeyBlob);

    //
    // Step 1: Validate input parameters
    //
    if (authContextHandle == NULL || !userKey || userKeySize == 0 || !boundKey || !boundKeySize)
    {
        return E_INVALIDARG;
    }

    // Resolve the handle to internal context
    NCRYPT_NGC_AUTHORIZATION_CONTEXT* authCtx;
    RETURN_IF_FAILED(AuthorizationContext::ResolveObject(authContextHandle, &authCtx));

    //
    // Step 2: Extract NGC public key and perform key establishment
    //
    unique_bcrypt_key ecdhKeyPair;
    unique_bcrypt_key helloPublicKeyHandle;
    unique_bcrypt_secret ecdhSecret;
    unique_secure_blob sharedSecret;
    RETURN_IF_FAILED(PerformECDHKeyEstablishment(authCtx, &ecdhKeyPair, &helloPublicKeyHandle, &ecdhSecret, &sharedSecret));

    //
    // Step 3: Compute KEK (hDerivedKey)
    //
    unique_bcrypt_key hDerivedKey;
    unique_sized_blob enclavePublicKeyBlob;
    RETURN_IF_FAILED(ComputeKEKFromSharedSecret(ecdhKeyPair.get(), sharedSecret.get(), sharedSecret.size(), &hDerivedKey, &enclavePublicKeyBlob));

    // Note: We are discarding the ECDH private key! (explicit for clarity)
    // 
    //  This means we can never re-materialize the KEK here, we need Hello to do that for us
    //  using the Hello private key (and the ephemeral public key)
    ecdhKeyPair.reset();

    // Clean up ECDH handles (keep shared secret and KEK for encryption)
    ecdhSecret.reset();

    //
    // Step 4: Encrypt the user key using the KEK
    //
    unique_sized_blob tmpBoundKey;
    RETURN_IF_FAILED(EncryptUserKeyWithKEK(hDerivedKey.get(), userKey, userKeySize, enclavePublicKeyBlob.get(), enclavePublicKeyBlob.size(), &tmpBoundKey));

    // Return the bound key - Transfer ownership
    *boundKey = tmpBoundKey.release();
    *boundKeySize = tmpBoundKey.size();

    return S_OK;
}

//
// Creates an encrypted NGC request for DeriveSharedSecret using the session key and ephemeral public key bytes
HRESULT CreateUserBoundKeyRequestForDeriveSharedSecret(
    _Inout_ USER_BOUND_KEY_SESSION_HANDLE sessionHandle,
    _In_ PCWSTR keyName,
    _In_reads_bytes_(publicKeyBytesSize) const void* publicKeyBytes,
    _In_ UINT32 publicKeyBytesSize,
    _Out_ UINT64* localNonce,
    _Outptr_result_buffer_(*encryptedRequestSize) void** encryptedRequest,
    _Out_ UINT32* encryptedRequestSize
)
{
    constexpr char header[] = "NgcReq"; // 7 bytes including null terminator
    constexpr UINT32 OPERATION_DERIVE_SHARED_SECRET = 2;

    //
    // Step 1: Validate input parameters and get session info
    //
    if (sessionHandle == NULL ||
        keyName == nullptr ||
        publicKeyBytes == nullptr ||
        publicKeyBytesSize == 0 ||
        localNonce == nullptr ||
        encryptedRequest == nullptr ||
        encryptedRequestSize == nullptr)
    {
        return E_INVALIDARG;
    }

    // Get session information
    USER_BOUND_KEY_SESSION_INTERNAL* sessionInfo;
    RETURN_IF_FAILED(SessionInfo::ResolveObject(sessionHandle, &sessionInfo));

    //
    // Step 2: Construct NGC request structure
    //

    // NGC request format with 7-byte header:
    // [7 bytes: header "NgcReq" including null terminator]
    // [4 bytes: operation type (DeriveSharedSecret = 2)]
    // [4 bytes: key name size]
    // [key name data]
    // [4 bytes: public key size]
    // [public key data]

    // Calculate total plaintext size
    UINT32 keyNameSize = static_cast<UINT32>(wcslen(keyName) * sizeof(wchar_t));
    UINT32 plaintextSize = sizeof(header) +   // 7-byte header including null terminator
        sizeof(UINT32) +    // operation type
        sizeof(UINT32) +    // key name size
        keyNameSize +       // key name data
        sizeof(UINT32) +    // public key size
        publicKeyBytesSize; // public key data

    // Allocate secure buffer for plaintext using RAII
    auto plaintextBuffer = make_unique_secure_blob(plaintextSize);
    if (!plaintextBuffer)
    {
        return E_OUTOFMEMORY;
    }

    // Build the plaintext buffer
    BYTE* pCurrentPos = plaintextBuffer.get();

    // Add 7-byte header first
    memcpy(pCurrentPos, header, sizeof(header));
    pCurrentPos += sizeof(header);

    // Add operation type
    memcpy(pCurrentPos, &OPERATION_DERIVE_SHARED_SECRET, sizeof(UINT32));
    pCurrentPos += sizeof(UINT32);

    // Add key name size
    memcpy(pCurrentPos, &keyNameSize, sizeof(UINT32));
    pCurrentPos += sizeof(UINT32);

    // Add key name data
    memcpy(pCurrentPos, keyName, keyNameSize);
    pCurrentPos += keyNameSize;

    // Add public key size
    memcpy(pCurrentPos, &publicKeyBytesSize, sizeof(UINT32));
    pCurrentPos += sizeof(UINT32);

    // Add public key data
    memcpy(pCurrentPos, publicKeyBytes, publicKeyBytesSize);

    //
    // Step 3: Handle nonce manipulation to prevent reuse
    //

    // Handle nonce manipulation to prevent reuse
    ULONG64 nonce = SessionInfo::ConsumeNextSessionNonce(sessionInfo);
    if (nonce >= MAX_REQUEST_NONCE)
    {
        return HRESULT_FROM_WIN32(ERROR_TOO_MANY_SECRETS);
    }

    // Create nonce buffer manually (instead of using crypto utility)
    BYTE nonceBuffer[AES_GCM_NONCE_SIZE] = {0};
    memcpy(&nonceBuffer[AES_GCM_NONCE_SIZE - sizeof(nonce)], &nonce, sizeof(nonce));

    //
    // Step 4: Encrypt the NGC request using BCrypt directly
    //

    // Set up AES-GCM authentication info
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BYTE authTag[AES_GCM_TAG_SIZE] = {0};
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = nonceBuffer;
    authInfo.cbNonce = AES_GCM_NONCE_SIZE;
    authInfo.pbTag = authTag;
    authInfo.cbTag = AES_GCM_TAG_SIZE;

    // Allocate buffer for encrypted data using RAII
    auto encryptedData = make_unique_sized_blob(plaintextSize);
    if (!encryptedData)
    {
        return E_OUTOFMEMORY;
    }

    // Encrypt the plaintext using BCrypt
    // In AES-GCM ciphertext and plaintext lengths are the same
    ULONG bytesEncrypted;
    RETURN_IF_FAILED(HRESULT_FROM_NT(BCryptEncrypt(
        sessionInfo->sessionKey.get(),
        plaintextBuffer.get(),
        plaintextSize,
        &authInfo,
        NULL,  // No IV for GCM (nonce is in authInfo)
        0,
        encryptedData.get(),
        plaintextSize,
        &bytesEncrypted,
        0
    )));

    //
    // Step 5: Construct final encrypted request format
    //

    // Final format: [8 bytes: nonce number][encrypted data][16 bytes: auth tag]
    UINT32 totalEncryptedSize = sizeof(nonce) + bytesEncrypted + AES_GCM_TAG_SIZE;

    // Allocate ciphertext buffer using RAII
    auto ciphertextBuffer = make_unique_sized_blob(totalEncryptedSize);
    if (!ciphertextBuffer)
    {
        return E_OUTOFMEMORY;
    }

    // Build the ciphertext buffer
    pCurrentPos = ciphertextBuffer.get();

    // Add nonce number
    memcpy(pCurrentPos, &nonce, sizeof(nonce));
    pCurrentPos += sizeof(nonce);

    // Add encrypted data
    memcpy(pCurrentPos, encryptedData.get(), encryptedData.size());
    pCurrentPos += encryptedData.size();

    // Add authentication tag
    memcpy(pCurrentPos, authTag, AES_GCM_TAG_SIZE);

    // Return
    *encryptedRequest = ciphertextBuffer.release();
    *encryptedRequestSize = ciphertextBuffer.size();
    *localNonce = nonce;

    return S_OK;
}

//
// Private helper functions for UnprotectUserBoundKey
//

//
// Structure to hold parsed bound key components
//
struct PARSED_BOUND_KEY_COMPONENTS
{
    unique_sized_blob enclavePublicKeyBlob; // Owning
    BYTE nonce[AES_GCM_NONCE_SIZE];
    const BYTE* pEncryptedUserKey;          // Non-owning
    UINT32 encryptedUserKeySize;
    const BYTE* pAuthTag;                   // Non-owning

    // Default constructor
    PARSED_BOUND_KEY_COMPONENTS() : pEncryptedUserKey(nullptr), encryptedUserKeySize(0), pAuthTag(nullptr)
    {
        memset(nonce, 0, sizeof(nonce));
    }

    //
    // Because this containts non-owning memory...
    //
    // - Delete copy
    PARSED_BOUND_KEY_COMPONENTS(const PARSED_BOUND_KEY_COMPONENTS&) = delete;
    PARSED_BOUND_KEY_COMPONENTS& operator=(const PARSED_BOUND_KEY_COMPONENTS&) = delete;
    // - Delete move
    PARSED_BOUND_KEY_COMPONENTS(PARSED_BOUND_KEY_COMPONENTS&&) = delete;
    PARSED_BOUND_KEY_COMPONENTS& operator=(PARSED_BOUND_KEY_COMPONENTS&&) = delete;
};

//
// Parse the bound key structure and extract all components
//
static HRESULT
ParseBoundKeyStructure(
    _In_reads_bytes_(boundKeySize) const BYTE* boundKey,
    _In_ UINT32 boundKeySize,
    _Out_ PARSED_BOUND_KEY_COMPONENTS* pComponents
)
{
    // Validate minimum bound key size
    constexpr UINT32 minBoundKeySize = sizeof(UINT32) + sizeof(UINT32) + AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE;
    if (boundKeySize < minBoundKeySize)
    {
        return NTE_BAD_DATA;
    }

    const BYTE* pCurrentPos = boundKey;

    // Read enclave public key blob size
    UINT32 enclavePublicKeyBlobSize = *reinterpret_cast<const UINT32*>(pCurrentPos);
    pCurrentPos += sizeof(UINT32);

    // Validate enclave public key blob size
    if (enclavePublicKeyBlobSize == 0 ||
        enclavePublicKeyBlobSize > KCM_PUBLIC_KEY_MAX_SIZE)
    {
        return NTE_BAD_DATA;
    }

    // Verify we have enough data for the public key blob
    if ((pCurrentPos - boundKey) + enclavePublicKeyBlobSize > boundKeySize)
    {
        return NTE_BAD_DATA;
    }

    // Extract and allocate enclave public key blob
    auto tmpEnclavePublicKeyBlob = make_unique_sized_blob(enclavePublicKeyBlobSize);
    if (!tmpEnclavePublicKeyBlob)
    {
        return E_OUTOFMEMORY;
    }

    memcpy(tmpEnclavePublicKeyBlob.get(), pCurrentPos, tmpEnclavePublicKeyBlob.size());
    pCurrentPos += enclavePublicKeyBlobSize;

    //
    // Parse components
    //

    // Extract nonce
    if (static_cast<UINT32>(pCurrentPos - boundKey) + AES_GCM_NONCE_SIZE > boundKeySize)
    {
        return NTE_BAD_DATA;
    }
    memcpy(pComponents->nonce, pCurrentPos, AES_GCM_NONCE_SIZE);
    pCurrentPos += AES_GCM_NONCE_SIZE;

    // Read encrypted user key size
    if ((pCurrentPos - boundKey) + sizeof(UINT32) > boundKeySize)
    {
        return NTE_BAD_DATA;
    }
    pComponents->encryptedUserKeySize = *reinterpret_cast<const UINT32*>(pCurrentPos);
    pCurrentPos += sizeof(UINT32);

    // Validate encrypted user key size
    if (pComponents->encryptedUserKeySize == 0 ||
        pComponents->encryptedUserKeySize > MAX_ENCRYPTED_USER_KEY_SIZE) // Reasonable upper limit
    {
        return NTE_BAD_DATA;
    }

    // Extract encrypted user key data
    if ((pCurrentPos - boundKey) + pComponents->encryptedUserKeySize + AES_GCM_TAG_SIZE > boundKeySize)
    {
        return NTE_BAD_DATA;
    }
    pComponents->pEncryptedUserKey = pCurrentPos;
    pCurrentPos += pComponents->encryptedUserKeySize;

    // Validate that we have exactly AES_GCM_TAG_SIZE bytes remaining for the authentication tag
    UINT32 remainingBytes = boundKeySize - static_cast<UINT32>(pCurrentPos - boundKey);
    if (remainingBytes != AES_GCM_TAG_SIZE)
    {
        return NTE_BAD_DATA;
    }

    pComponents->enclavePublicKeyBlob = wil_raw::move(tmpEnclavePublicKeyBlob);

    // Extract authentication tag - now we know we have exactly the right amount of data
    pComponents->pAuthTag = pCurrentPos;

    return S_OK;
}

//
// Step 2: Decrypt the auth context blob using BCrypt APIs
//
static HRESULT
DecryptAndUntagSecret(
    _In_ BCRYPT_KEY_HANDLE sessionKey,
    _In_ const BYTE* secretBlob,
    _In_ UINT32 secretBlobSize,
    _Out_ unique_secure_blob* pDecryptedSecret,
    _In_ ULONG64 nonceNumber
)
{
    constexpr UINT32 VTL1_TAG_SIZE = AES_GCM_TAG_SIZE;       // AES-GCM auth tag at end
    constexpr ULONG64 c_responderBitFlip = 0x80000000;

    // The auth context blob was encrypted using ClientAuth::EncryptResponse which uses
    // VTL1 mutual authentication protocol with AES-GCM format.
    // IMPORTANT: EncryptResponse (new protocol) format is: [encrypted data][16-byte auth tag]
    // The nonce is NOT stored in the encrypted blob - it must be provided separately!

    // For EncryptResponse format: [encrypted data][16-byte auth tag]
    if (secretBlobSize < VTL1_TAG_SIZE)
    {
        return NTE_BAD_DATA;
    }

    ULONG64 nonce = nonceNumber ^ c_responderBitFlip;  // Apply responder bit flip as per VTL1 protocol

    // Create nonce buffer manually (instead of using crypto utility)
    BYTE nonceBuffer[AES_GCM_NONCE_SIZE] = {0}; // Fill with 0s
    memcpy(&nonceBuffer[AES_GCM_NONCE_SIZE - sizeof(nonce)], &nonce, sizeof(nonce));

    // Extract components from the EncryptResponse encrypted blob
    // Format: [encrypted data][16-byte auth tag] - NO NONCE stored in blob
    BYTE* pEncryptedData = const_cast<BYTE*>(secretBlob);
    UINT32 encryptedDataSize = secretBlobSize - VTL1_TAG_SIZE;
    BYTE* pAuthTag = pEncryptedData + encryptedDataSize;

    // Set up AES-GCM authentication info for VTL1 format
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = nonceBuffer;
    authInfo.cbNonce = AES_GCM_NONCE_SIZE;
    authInfo.pbTag = reinterpret_cast<PUCHAR>(pAuthTag);
    authInfo.cbTag = VTL1_TAG_SIZE;

    // Allocate buffer for decrypted data using RAII
    auto decryptedSecret = make_unique_secure_blob(encryptedDataSize);
    if (!decryptedSecret)
    {
        return E_OUTOFMEMORY;
    }

    // Perform AES-GCM decryption using VTL1 format
    ULONG bytesDecrypted = 0;
    RETURN_IF_FAILED(HRESULT_FROM_NT(BCryptDecrypt(
        sessionKey,
        reinterpret_cast<PUCHAR>(pEncryptedData),
        encryptedDataSize,
        &authInfo,
        NULL,  // No IV for GCM (nonce is in authInfo)
        0,
        decryptedSecret.get(),
        decryptedSecret.size(),
        &bytesDecrypted,
        0
    )));

    if (bytesDecrypted != decryptedSecret.size())
    {
        return E_UNEXPECTED;
    }

    *pDecryptedSecret = wil_raw::move(decryptedSecret);

    return S_OK;
}

// Decrypt the user key from material from disk
HRESULT UnprotectUserBoundKey(
    _In_ USER_BOUND_KEY_SESSION_HANDLE sessionHandle,
    _In_ USER_BOUND_KEY_AUTH_CONTEXT_HANDLE /*authContext*/,
    _In_reads_bytes_(sessionEncryptedDerivedSecretSize) const void* sessionEncryptedDerivedSecretBlob,
    _In_ UINT32 sessionEncryptedDerivedSecretSize,
    _In_reads_bytes_(encryptedUserBoundKeySize) const void* encryptedUserBoundKey,
    _In_ UINT32 encryptedUserBoundKeySize,
    _In_ UINT64 localNonce,
    _Outptr_result_buffer_(*userKeySize) void** userKey,
    _Inout_ UINT32* userKeySize
)
{
    const BYTE* sessionEncryptedDerivedSecret = reinterpret_cast<const BYTE*>(sessionEncryptedDerivedSecretBlob);

    //
    // Step 1: Validate input parameters
    //
    if (!sessionEncryptedDerivedSecret ||
        sessionEncryptedDerivedSecretSize == 0 ||
        !encryptedUserBoundKey ||
        encryptedUserBoundKeySize == 0 ||
        !userKey ||
        !userKeySize)
    {
        return E_INVALIDARG;
    }

    // Get session information    
    USER_BOUND_KEY_SESSION_INTERNAL* sessionInfo;
    RETURN_IF_FAILED(SessionInfo::ResolveObject(sessionHandle, &sessionInfo));

    //
    // Step 2: Decrypt the secret using session key and nonce
    //
    unique_secure_blob decryptedSharedSecret;
    RETURN_IF_FAILED(DecryptAndUntagSecret(
        sessionInfo->sessionKey.get(),
        sessionEncryptedDerivedSecret,
        sessionEncryptedDerivedSecretSize,
        &decryptedSharedSecret,
        localNonce));

    //
    // Step 3: Generate KEK using the shared secret as key material
    //
    unique_bcrypt_key kek;
    RETURN_IF_FAILED(HRESULT_FROM_NT(BCryptGenerateSymmetricKey(
        BCRYPT_AES_GCM_ALG_HANDLE,
        &kek,
        NULL,
        0,
        decryptedSharedSecret.get(),
        decryptedSharedSecret.size(),
        0)));

    //
    // Step 4: Parse the bound key structure
    //
    PARSED_BOUND_KEY_COMPONENTS boundKeyComponents{};
    RETURN_IF_FAILED(ParseBoundKeyStructure(reinterpret_cast<const BYTE*>(encryptedUserBoundKey), encryptedUserBoundKeySize, &boundKeyComponents));

    //
    // Step 5: Decrypt the user key using AES-GCM
    //

    // Allocate secure buffer for decrypted user key using RAII
    auto decryptedUserKey = make_unique_secure_blob(boundKeyComponents.encryptedUserKeySize);
    if (!decryptedUserKey)
    {
        return E_OUTOFMEMORY;
    }

    // Set up AES-GCM authentication info
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = boundKeyComponents.nonce;
    authInfo.cbNonce = AES_GCM_NONCE_SIZE;
    authInfo.pbTag = reinterpret_cast<PUCHAR>(const_cast<BYTE*>(boundKeyComponents.pAuthTag));
    authInfo.cbTag = AES_GCM_TAG_SIZE;

    // Perform AES-GCM decryption
    ULONG bytesDecrypted = 0;
    RETURN_IF_FAILED(HRESULT_FROM_NT(BCryptDecrypt(
        kek.get(),
        reinterpret_cast<PUCHAR>(const_cast<BYTE*>(boundKeyComponents.pEncryptedUserKey)),
        boundKeyComponents.encryptedUserKeySize,
        &authInfo,
        NULL,  // No IV for GCM (nonce is in authInfo)
        0,
        decryptedUserKey.get(),
        decryptedUserKey.size(),
        &bytesDecrypted,
        0
    )));

    if (bytesDecrypted != decryptedUserKey.size())
    {
        return E_UNEXPECTED;
    }

    // Return the decrypted user key
    *userKey = decryptedUserKey.release();
    *userKeySize = decryptedUserKey.size();

    return S_OK;
}

//
// Creates an encrypted NGC request for RetrieveAuthorizationContext using the session key
HRESULT CreateUserBoundKeyRequestForRetrieveAuthorizationContext(
    _In_ USER_BOUND_KEY_SESSION_HANDLE sessionHandle,
    _In_ PCWSTR keyName,
    _Out_ UINT64* localNonce,
    _Outptr_result_buffer_(*encryptedRequestSize) void** encryptedRequest,
    _Out_ UINT32* encryptedRequestSize
)
{
    constexpr char header[] = "NgcReq"; // 7 bytes including null terminator
    constexpr UINT32 OPERATION_RETRIEVE_AUTHORIZATION_CONTEXT = 9; // Different operation ID

    //
    // Step 1: Validate input parameters and get session info
    //
    if (sessionHandle == NULL ||
        !keyName ||
        !encryptedRequest ||
        !encryptedRequestSize)
    {
        return E_INVALIDARG;
    }

    // Get session information
    USER_BOUND_KEY_SESSION_INTERNAL* sessionInfo;
    RETURN_IF_FAILED(SessionInfo::ResolveObject(sessionHandle, &sessionInfo));

    //
    // Step 2: Construct NGC request structure
    //

    // NGC request format with 7-byte header for RetrieveAuthorizationContext:
    // [7 bytes: header "NgcReq" including null terminator]
    // [4 bytes: operation type (RetrieveAuthorizationContext = 9)]
    // [4 bytes: key name size]
    // [key name data]
    // Note: Unlike DeriveSharedSecret, this operation doesn't require public key data

    // Calculate total plaintext size
    UINT32 keyNameSize = static_cast<UINT32>(wcslen(keyName) * sizeof(wchar_t));
    UINT32 plaintextSize = sizeof(header) +   // 7-byte header including null terminator
        sizeof(UINT32) +    // operation type
        sizeof(UINT32) +    // key name size
        keyNameSize;        // key name data

    // Allocate plaintext buffer using RAII
    auto plaintextBuffer = make_unique_sized_blob(plaintextSize);
    if (!plaintextBuffer)
    {
        return E_OUTOFMEMORY;
    }

    // Build the plaintext buffer
    BYTE* pCurrentPos = plaintextBuffer.get();

    // Add 7-byte header first
    memcpy(pCurrentPos, header, sizeof(header));
    pCurrentPos += sizeof(header);

    // Add operation type
    memcpy(pCurrentPos, &OPERATION_RETRIEVE_AUTHORIZATION_CONTEXT, sizeof(UINT32));
    pCurrentPos += sizeof(UINT32);

    // Add key name size
    memcpy(pCurrentPos, &keyNameSize, sizeof(UINT32));
    pCurrentPos += sizeof(UINT32);

    // Add key name data
    memcpy(pCurrentPos, keyName, keyNameSize);

    //
    // Step 3: Handle nonce manipulation to prevent reuse
    //

    // Handle nonce manipulation to prevent reuse
    ULONG64 nonce = SessionInfo::ConsumeNextSessionNonce(sessionInfo);
    if (nonce >= MAX_REQUEST_NONCE)
    {
        return HRESULT_FROM_WIN32(ERROR_TOO_MANY_SECRETS);
    }

    // Create nonce buffer manually (instead of using crypto utility)
    BYTE nonceBuffer[AES_GCM_NONCE_SIZE] = {0};
    memcpy(&nonceBuffer[AES_GCM_NONCE_SIZE - sizeof(nonce)], &nonce, sizeof(nonce));

    //
    // Step 4: Encrypt the NGC request using BCrypt directly
    //

    // Set up AES-GCM authentication info
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BYTE authTag[AES_GCM_TAG_SIZE] = {0};
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = nonceBuffer;
    authInfo.cbNonce = AES_GCM_NONCE_SIZE;
    authInfo.pbTag = authTag;
    authInfo.cbTag = AES_GCM_TAG_SIZE;

    // Allocate buffer for encrypted data using RAII
    auto encryptedData = make_unique_sized_blob(plaintextSize);

    // Encrypt the plaintext using BCrypt
    // In AES-GCM ciphertext and plaintext lengths are the same
    ULONG bytesEncrypted = 0;
    RETURN_IF_FAILED(HRESULT_FROM_NT(BCryptEncrypt(
        sessionInfo->sessionKey.get(),
        plaintextBuffer.get(),
        plaintextSize,
        &authInfo,
        NULL,  // No IV for GCM (nonce is in authInfo)
        0,
        encryptedData.get(),
        encryptedData.size(),
        &bytesEncrypted,
        0
    )));

    if (bytesEncrypted != encryptedData.size())
    {
        return E_UNEXPECTED;
    }

    //
    // Step 5: Construct final encrypted request format
    //

    // Final format: [8 bytes: nonce number][encrypted data][16 bytes: auth tag]
    UINT32 totalEncryptedSize = sizeof(nonce) + bytesEncrypted + AES_GCM_TAG_SIZE;

    // Allocate ciphertext buffer using RAII
    auto ciphertextBuffer = make_unique_sized_blob(totalEncryptedSize);
    if (!ciphertextBuffer)
    {
        return E_OUTOFMEMORY;
    }

    // Build the ciphertext buffer
    pCurrentPos = ciphertextBuffer.get();

    // Add nonce number
    memcpy(pCurrentPos, &nonce, sizeof(nonce));
    pCurrentPos += sizeof(nonce);

    // Add encrypted data
    memcpy(pCurrentPos, encryptedData.get(), encryptedData.size());
    pCurrentPos += encryptedData.size();

    // Add authentication tag
    memcpy(pCurrentPos, authTag, AES_GCM_TAG_SIZE);

    // Return
    *localNonce = nonce;
    *encryptedRequest = ciphertextBuffer.release();
    *encryptedRequestSize = totalEncryptedSize;

    return S_OK;
}

