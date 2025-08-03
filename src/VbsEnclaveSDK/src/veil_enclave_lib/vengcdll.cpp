// Copyright (c) Microsoft Corporation.
//

#include "pch.h"
#include "vengcdll.h"  // Use quotes for local header

//
// Implementation of vengcdll exports for VTL1 enclave environment
// This file provides implementations for functions that support user bound keys in VTL1
//

// Note: Removed custom CoTaskMemFree implementation to avoid conflicts with Windows SDK
// The Windows SDK already provides the correct CoTaskMemFree implementation

// Forward declarations for NGC types
// Structure to return values for NCRYPT_NGC_AUTHORIZATION_CONTEXT_PROPERTY
typedef struct _NCRYPT_NGC_AUTHORIZATION_CONTEXT{
    DWORD structSize;
    BOOL isSecureIdOwnerId;
    KEY_CREDENTIAL_CACHE_CONFIG cacheConfig;
    DWORD keyNameLength;
    WCHAR keyName[NGC_KEY_NAME_BUFFER_SIZE];
    DWORD trustletSignedPublicKeyByteCount;
    BYTE trustletSignedPublicKey[1];
} NCRYPT_NGC_AUTHORIZATION_CONTEXT, * PNCRYPT_NGC_AUTHORIZATION_CONTEXT;

// Use HeapAlloc/HeapFree instead of malloc/free for VTL1 compatibility
#define VengcAlloc(size) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (size))
#define VengcFree(ptr) HeapFree(GetProcessHeap(), 0, (ptr))

// Custom secure free function for VTL1 context
void VengcSecureFree(void* ptr, size_t size)
{
    if (ptr && size > 0)
    {
        // Zero the memory before freeing
        RtlSecureZeroMemory(ptr, size);
        VengcFree(ptr);
    }
}

// Structure to hold parsed NGC session challenge data
typedef struct _NGC_CHALLENGE_PARSE_RESULT {
    uint8_t* challengeBytes;
    UINT32 challengeBytesSize;
    PS_TRUSTLET_TKSESSION_ID sessionId;
} NGC_CHALLENGE_PARSE_RESULT;

// Internal structure to hold decrypted auth context data
typedef struct _USER_BOUND_KEY_AUTH_CONTEXT_INTERNAL {
    BYTE* pDecryptedAuthContext;
    UINT32 decryptedSize;
} USER_BOUND_KEY_AUTH_CONTEXT_INTERNAL, * PUSER_BOUND_KEY_AUTH_CONTEXT_INTERNAL;

_Success_(return == S_OK)
HRESULT add_buffer_bytes(
    _Inout_updates_bytes_(dest_capacity) uint8_t * dest,
    _Inout_ size_t * dest_len,
    _In_reads_bytes_(src_len) const uint8_t * src,
    _In_ size_t src_len,
    _In_ size_t dest_capacity)
{
    // Validate input parameters
    if (dest == NULL || dest_len == NULL || src == NULL)
    {
        return E_INVALIDARG;
    }

    // Check for integer overflow in addition
    if (*dest_len > SIZE_MAX - src_len)
    {
        return HRESULT_FROM_WIN32(ERROR_ARITHMETIC_OVERFLOW);
    }

    // Check buffer capacity
    if (*dest_len + src_len > dest_capacity)
    {
        return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
    }

    // Check for buffer overlap - buffers from VTL0 could potentially overlap
    // Check if src buffer overlaps with the destination write area
    uint8_t* dest_write_start = dest + *dest_len;
    uint8_t* dest_write_end = dest_write_start + src_len;
    const uint8_t* src_end = src + src_len;

    if ((src >= dest_write_start && src < dest_write_end) ||
        (src_end > dest_write_start && src_end <= dest_write_end) ||
        (src <= dest_write_start && src_end >= dest_write_end))
    {
        return E_INVALIDARG; // Buffers overlap - unsafe to proceed
    }

    memcpy(dest + *dest_len, src, src_len);
    *dest_len += src_len;
    return S_OK;
}

//
// Parse NGC session challenge to extract challenge bytes and session ID
// Returns parsed challenge data in the result structure
//
HRESULT ParseNgcSessionChallenge(
    _In_ const void* challenge,
    _In_ UINT32 challengeSize,
    _Out_ NGC_CHALLENGE_PARSE_RESULT * result)
{
    if (challenge == NULL || result == NULL)
    {
        return E_INVALIDARG;
    }

    // Initialize result structure
    result->challengeBytes = NULL;
    result->challengeBytesSize = 0;
    memset(&result->sessionId, 0, sizeof(result->sessionId));

    const uint8_t* challengePtr = (const uint8_t*)challenge;

    // Extract session ID from first bytes if challenge is large enough
    if (challengeSize >= sizeof(PS_TRUSTLET_TKSESSION_ID))
    {
        memcpy(&result->sessionId, challengePtr, sizeof(PS_TRUSTLET_TKSESSION_ID));
        // Remaining bytes are the actual challenge
        UINT32 remainingSize = challengeSize - sizeof(PS_TRUSTLET_TKSESSION_ID);
        if (remainingSize > 0)
        {
            result->challengeBytes = (uint8_t*)VengcAlloc(remainingSize);
            if (result->challengeBytes == NULL)
            {
                return E_OUTOFMEMORY;
            }
            memcpy(result->challengeBytes, challengePtr + sizeof(PS_TRUSTLET_TKSESSION_ID), remainingSize);
            result->challengeBytesSize = remainingSize;
        }
    }
    else
    {
        // If challenge is too small, treat entire challenge as challenge bytes
        result->challengeBytes = (uint8_t*)VengcAlloc(challengeSize);
        if (result->challengeBytes == NULL)
        {
            return E_OUTOFMEMORY;
        }
        memcpy(result->challengeBytes, challengePtr, challengeSize);
        result->challengeBytesSize = challengeSize;
    }

    return S_OK;
}


//
// Private helper functions for InitializeUserBoundKeySessionInfo
//

//
// Step 1: Validate input parameters for session initialization
//
static HRESULT
ValidateSessionInputParameters(
    _In_ const void* challenge,
    _In_ UINT32 challengeSize,
    _In_ void** report,
    _In_ UINT32 * reportSize,
    _In_ UINT_PTR * sessionKeyPtr,
    _In_ UINT32 * sessionKeySize
)
{
    if (challenge == NULL || challengeSize == 0)
    {
        return E_INVALIDARG;
    }

    if (report == NULL || reportSize == NULL || sessionKeyPtr == NULL || sessionKeySize == NULL)
    {
        return E_POINTER;
    }

    // Initialize output parameters
    *report = NULL;
    *reportSize = 0;
    *sessionKeyPtr = 0;
    *sessionKeySize = 0;

    return S_OK;
}

//
// Step 2: Generate session key for encryption
//
static HRESULT
GenerateSessionKey(
    _In_ UINT32 sessionKeySize,
    _Out_ BCRYPT_KEY_HANDLE * phSessionKey,
    _Out_ PUCHAR * ppSessionKeyBytes
)
{
    HRESULT hr = S_OK;
    PUCHAR pSessionKeyBytes = NULL;
    BCRYPT_KEY_HANDLE hSessionKey = NULL;

    // Allocate memory for key bytes
    pSessionKeyBytes = (PUCHAR)VengcAlloc(sessionKeySize);
    if (pSessionKeyBytes == NULL)
    {
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }

    // Generate cryptographically secure random key bytes
    hr = BCryptGenRandom(NULL, pSessionKeyBytes, sessionKeySize, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (FAILED(hr))
    {
        goto cleanup;
    }

    // Create symmetric key from the generated bytes using AES-GCM algorithm
    hr = BCryptGenerateSymmetricKey(BCRYPT_AES_GCM_ALG_HANDLE, &hSessionKey, NULL, 0, pSessionKeyBytes, sessionKeySize, 0);
    if (FAILED(hr))
    {
        goto cleanup;
    }

    // Success - transfer ownership to caller
    *phSessionKey = hSessionKey;
    *ppSessionKeyBytes = pSessionKeyBytes;
    hSessionKey = NULL;
    pSessionKeyBytes = NULL;

    cleanup:
    if (pSessionKeyBytes != NULL)
    {
        VengcSecureFree(pSessionKeyBytes, sessionKeySize);
    }
    if (hSessionKey != NULL)
    {
        BCryptDestroyKey(hSessionKey);
    }

    return hr;
}

//
// Step 3: Generate attestation report with session key and challenge
//
static HRESULT
GenerateAttestationReport(
    _In_ const void* challenge,
    _In_ UINT32 challengeSize,
    _In_ PUCHAR pSessionKeyBytes,
    _In_ UINT32 sessionKeySize,
    _Out_ void** ppAttestationReport,
    _Out_ UINT32 * pAttestationReportSize,
    _Out_ PS_TRUSTLET_TKSESSION_ID * pSessionId
)
{
    HRESULT hr = S_OK;
    NGC_CHALLENGE_PARSE_RESULT parseResult = {0};
    void* pAttestationReport = NULL;
    UINT32 attestationReportSize = 0;

    // Declare all variables at the beginning to avoid goto initialization issues
    uint8_t attestationBuffer[NGC_ATTESTATION_BUFFER_SIZE];
    size_t attestationBufferLen = 0;
    size_t attestationBufferCapacity = sizeof(attestationBuffer);
    uint8_t attestStr[8] = {'a', 't', 't', 'e', 's', 't', 0, 0};
    uint8_t enclaveData[ENCLAVE_REPORT_DATA_LENGTH] = {0};
    size_t copyLen = 0;
    UINT32 tempReportSize = 0;

    // Parse the NGC session challenge
    hr = ParseNgcSessionChallenge(challenge, challengeSize, &parseResult);
    if (FAILED(hr))
    {
        goto cleanup;
    }

    // Add "attest" string (up to 8 bytes)
    hr = add_buffer_bytes(attestationBuffer, &attestationBufferLen, attestStr, 6, attestationBufferCapacity);
    if (FAILED(hr))
    {
        goto cleanup;
    }

    // Add challenge bytes
    if (parseResult.challengeBytes && parseResult.challengeBytesSize > 0)
    {
        hr = add_buffer_bytes(attestationBuffer, &attestationBufferLen,
                            parseResult.challengeBytes, parseResult.challengeBytesSize,
                            attestationBufferCapacity);
        if (FAILED(hr))
        {
            goto cleanup;
        }
    }

    // Add session key bytes
    hr = add_buffer_bytes(attestationBuffer, &attestationBufferLen, pSessionKeyBytes, sessionKeySize, attestationBufferCapacity);
    if (FAILED(hr))
    {
        goto cleanup;
    }

    // Calculate copy length and prepare enclaveData buffer
    copyLen = attestationBufferLen < ENCLAVE_REPORT_DATA_LENGTH ? attestationBufferLen : ENCLAVE_REPORT_DATA_LENGTH;
    memcpy(enclaveData, attestationBuffer, copyLen);

    // Call Windows enclave attestation API to get size
    hr = EnclaveGetAttestationReport(enclaveData, NULL, 0, &tempReportSize);
    if (FAILED(hr))
    {
        goto cleanup;
    }

    attestationReportSize = tempReportSize;

    // Allocate buffer for the actual attestation report
    pAttestationReport = VengcAlloc(attestationReportSize);
    if (pAttestationReport == NULL)
    {
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }

    // Get the actual attestation report
    hr = EnclaveGetAttestationReport(enclaveData, pAttestationReport, attestationReportSize, &tempReportSize);
    if (FAILED(hr))
    {
        goto cleanup;
    }

    // Success - transfer ownership to caller
    *ppAttestationReport = pAttestationReport;
    *pAttestationReportSize = attestationReportSize;
    *pSessionId = parseResult.sessionId;
    pAttestationReport = NULL;

    cleanup:
        // Clean up parse result
    if (parseResult.challengeBytes)
    {
        VengcSecureFree(parseResult.challengeBytes, parseResult.challengeBytesSize);
    }

    if (pAttestationReport != NULL)
    {
        VengcSecureFree(pAttestationReport, attestationReportSize);
    }

    return hr;
}

//
// Step 4: Encrypt attestation report using EnclaveEncryptDataForTrustlet
//
static HRESULT
EncryptAttestationReport(
    _In_ void* pAttestationReport,
    _In_ UINT32 attestationReportSize,
    _In_ PS_TRUSTLET_TKSESSION_ID sessionId,
    _Out_ void** ppEncryptedReport,
    _Out_ UINT32 * pEncryptedReportSize
)
{
    HRESULT hr = S_OK;
    void* pEncryptedReport = NULL;
    UINT32 encryptedReportSize = 0;

    // Set up trustlet binding data
    TRUSTLET_BINDING_DATA trustletData;
    trustletData.TrustletIdentity = TRUSTLETIDENTITY_NGC;
    trustletData.TrustletSessionId = sessionId;
    trustletData.TrustletSvn = 0;
    trustletData.Reserved1 = 0;
    trustletData.Reserved2 = 0;

    // Get the required buffer size for encrypted data
    UINT32 tempEncryptedSize = 0;
    hr = EnclaveEncryptDataForTrustlet(
        pAttestationReport,
        attestationReportSize,
        &trustletData,
        NULL,
        0,
        &tempEncryptedSize
    );
    if (FAILED(hr))
    {
        goto cleanup;
    }

    encryptedReportSize = tempEncryptedSize;
    pEncryptedReport = VengcAlloc(encryptedReportSize);
    if (pEncryptedReport == NULL)
    {
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }

    // Perform the actual encryption
    hr = EnclaveEncryptDataForTrustlet(
        pAttestationReport,
        attestationReportSize,
        &trustletData,
        pEncryptedReport,
        encryptedReportSize,
        &tempEncryptedSize
    );
    if (FAILED(hr))
    {
        goto cleanup;
    }

    // Update the actual encrypted size
    encryptedReportSize = tempEncryptedSize;

    // Success - transfer ownership to caller
    *ppEncryptedReport = pEncryptedReport;
    *pEncryptedReportSize = encryptedReportSize;
    pEncryptedReport = NULL;

    cleanup:
    if (pEncryptedReport != NULL)
    {
        VengcSecureFree(pEncryptedReport, encryptedReportSize);
    }

    return hr;
}

// Attestation report generation API for user bound keys.
// Generates a session key, passes session key and provided challenge to EnclaveGetAttestationReport,
// encrypts the attestation report with EnclaveEncryptDataForTrustlet, returns the encrypted report. 
HRESULT InitializeUserBoundKeySessionInfo(
    _In_reads_bytes_(challengeSize) const void* challenge,
    _In_ UINT32 challengeSize,
    _Outptr_result_buffer_(*reportSize) void** report,
    _Out_ UINT32 * reportSize,
    _Out_ UINT_PTR * sessionKey,
    _Out_ UINT32 * sessionKeySize
)
{
    HRESULT hr = S_OK;
    void* pSessionKey = NULL;
    void* pAttestationReport = NULL;
    void* pEncryptedReport = NULL;
    UINT32 attestationReportSize = 0;
    UINT32 encryptedReportSize = 0;
    const UINT32 SESSION_KEY_SIZE = AES_256_KEY_SIZE_BYTES; // 256-bit AES key
    BCRYPT_KEY_HANDLE hSessionKey = NULL;
    PUCHAR pSessionKeyBytes = NULL;
    PS_TRUSTLET_TKSESSION_ID sessionId = {0};

    //
    // Step 1: Validate input parameters
    //
    hr = ValidateSessionInputParameters(challenge, challengeSize, report, reportSize, sessionKey, sessionKeySize);
    if (FAILED(hr))
    {
        goto cleanup;
    }

    //
    // Step 2: Generate session key for encryption
    //
    hr = GenerateSessionKey(SESSION_KEY_SIZE, &hSessionKey, &pSessionKeyBytes);
    if (FAILED(hr))
    {
        goto cleanup;
    }

    // Store the session key handle for later use
    pSessionKey = (void*)hSessionKey;

    //
    // Step 3: Generate attestation report with session key and challenge
    //
    hr = GenerateAttestationReport(challenge, challengeSize, pSessionKeyBytes, SESSION_KEY_SIZE,
                                  &pAttestationReport, &attestationReportSize, &sessionId);
    if (FAILED(hr))
    {
        goto cleanup;
    }

    //
    // Step 4: Encrypt attestation report using EnclaveEncryptDataForTrustlet
    //
    hr = EncryptAttestationReport(pAttestationReport, attestationReportSize, sessionId,
                                 &pEncryptedReport, &encryptedReportSize);
    if (FAILED(hr))
    {
        goto cleanup;
    }

    //
    // Step 5: Return encrypted report and session key information
    //
    *report = pEncryptedReport;
    *reportSize = encryptedReportSize;
    *sessionKey = (UINT_PTR)pSessionKey;
    *sessionKeySize = SESSION_KEY_SIZE;

    // Clear local pointers so they won't be freed in cleanup
    pEncryptedReport = NULL;
    pSessionKey = NULL;

    cleanup:
        // Clean up on failure
    if (FAILED(hr))
    {
        if (pEncryptedReport)
        {
            VengcSecureFree(pEncryptedReport, encryptedReportSize);
        }
        if (pSessionKey)
        {
            // pSessionKey is actually the BCrypt key handle, so destroy it
            BCryptDestroyKey((BCRYPT_KEY_HANDLE)pSessionKey);
        }
    }

    if (pAttestationReport)
    {
        VengcSecureFree(pAttestationReport, attestationReportSize);
    }

    if (pSessionKeyBytes)
    {
        VengcSecureFree(pSessionKeyBytes, SESSION_KEY_SIZE);
    }

    return hr;
}

BOOL CloseUserBoundKeyAuthContextHandle(
    _In_ USER_BOUND_KEY_AUTH_CONTEXT_HANDLE handle)
{
    UNREFERENCED_PARAMETER(handle);
    return TRUE;
}

//
// Private helper functions for GetUserBoundKeyCreationAuthContext
//

//
// Step 1: Validate input parameters for auth context creation
//
static HRESULT
ValidateAuthContextInputParameters(
    _In_ UINT_PTR sessionKeyPtr,
    _In_ const void* authContextBlob,
    _In_ UINT32 authContextBlobSize,
    _In_ USER_BOUND_KEY_AUTH_CONTEXT_HANDLE * authContextHandle
)
{
    if (authContextBlob == NULL || authContextHandle == NULL)
    {
        return E_INVALIDARG;
    }

    if (authContextBlobSize == 0 || sessionKeyPtr == 0)
    {
        return E_INVALIDARG;
    }

    // Initialize output parameter
    *authContextHandle = NULL;

    return S_OK;
}

//
// Step 2: Decrypt the auth context blob using BCrypt APIs
//
static HRESULT
DecryptAuthContextBlob(
    _In_ UINT_PTR sessionKeyPtr,
    _In_ const void* authContextBlob,
    _In_ UINT32 authContextBlobSize,
    _Out_ BYTE * * ppDecryptedAuthContext,
    _Out_ UINT32 * pDecryptedSize
)
{
    HRESULT hr = S_OK;
    BYTE* pDecryptedAuthContext = NULL;
    UINT32 decryptedSize = 0;

    // Declare all variables at the beginning to avoid goto initialization issues
    BCRYPT_KEY_HANDLE hSessionKey = NULL;
    const UINT32 VTL1_NONCE_SIZE = 8;      // ULONG64 nonce at beginning
    const UINT32 VTL1_TAG_SIZE = AES_GCM_TAG_SIZE;       // AES-GCM auth tag at end
    const UINT32 MIN_ENCRYPTED_BLOB_SIZE = VTL1_NONCE_SIZE + VTL1_TAG_SIZE;
    const UINT64 c_responderBitFlip = 0x80000000ULL;
    const BYTE* pNonceBytes = NULL;
    UINT64 rawNonce = 0;
    UINT64 nonce = 0;
    const BYTE* pEncryptedData = NULL;
    UINT32 encryptedDataSize = 0;
    const BYTE* pAuthTag = NULL;
    BYTE nonceBuffer[AES_GCM_NONCE_SIZE] = {0}; // Fill with 0s
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    ULONG bytesDecrypted = 0;

    // The auth context blob was encrypted using ClientAuth::EncryptData which uses
    // VTL1 mutual authentication protocol with AES-GCM format:
    // Format: [8-byte nonce][encrypted data][16-byte auth tag]

    hSessionKey = (BCRYPT_KEY_HANDLE)sessionKeyPtr;
    if (hSessionKey == NULL)
    {
        hr = E_INVALIDARG;
        goto cleanup;
    }

    if (authContextBlobSize < MIN_ENCRYPTED_BLOB_SIZE)
    {
        hr = E_INVALIDARG;
        goto cleanup;
    }

    // Extract components from the VTL1 encrypted blob
    // Format: [8-byte nonce][encrypted data][16-byte auth tag]
    pNonceBytes = (const BYTE*)authContextBlob;
    rawNonce = *((UINT64*)pNonceBytes);  // Extract the 8-byte nonce

    // Apply VTL1 responder bit flip to transform request nonce to response nonce
    nonce = rawNonce ^ c_responderBitFlip;

    pEncryptedData = pNonceBytes + VTL1_NONCE_SIZE;
    encryptedDataSize = authContextBlobSize - VTL1_NONCE_SIZE - VTL1_TAG_SIZE;
    pAuthTag = pEncryptedData + encryptedDataSize;

    // Add nonce value towards the end of the buffer (last 8 bytes)
    memcpy(&nonceBuffer[AES_GCM_NONCE_SIZE - sizeof(nonce)], &nonce, sizeof(nonce));

    // Set up AES-GCM authentication info for VTL1 format
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = nonceBuffer;
    authInfo.cbNonce = AES_GCM_NONCE_SIZE;
    authInfo.pbTag = (PUCHAR)pAuthTag;
    authInfo.cbTag = VTL1_TAG_SIZE;

    // Allocate buffer for decrypted data
    pDecryptedAuthContext = (BYTE*)VengcAlloc(encryptedDataSize);
    if (pDecryptedAuthContext == NULL)
    {
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }

    // Perform AES-GCM decryption using VTL1 format
    hr = BCryptDecrypt(
        hSessionKey,
        (PUCHAR)pEncryptedData,
        encryptedDataSize,
        &authInfo,
        NULL,  // No IV for GCM (nonce is in authInfo)
        0,
        pDecryptedAuthContext,
        encryptedDataSize,
        &bytesDecrypted,
        0
    );

    if (FAILED(hr))
    {
        goto cleanup;
    }

    decryptedSize = bytesDecrypted;

    if (pDecryptedAuthContext == NULL || decryptedSize == 0)
    {
        hr = E_UNEXPECTED;
        goto cleanup;
    }

    // Success - transfer ownership to caller
    *ppDecryptedAuthContext = pDecryptedAuthContext;
    *pDecryptedSize = decryptedSize;
    pDecryptedAuthContext = NULL;

    cleanup:
    if (pDecryptedAuthContext != NULL)
    {
        VengcSecureFree(pDecryptedAuthContext, decryptedSize);
    }

    return hr;
}

// Called as part of the flow when creating a new user bound key.
// Decrypts the auth context blob provided by NGC and returns a handle to the decrypted blob
HRESULT GetUserBoundKeyCreationAuthContext(
    _In_ UINT_PTR sessionKeyPtr,
    _In_reads_bytes_(authContextBlobSize) const void* authContextBlob, // auth context generated as part of RequestCreateAsync
    _In_ UINT32 authContextBlobSize,
    _Out_ USER_BOUND_KEY_AUTH_CONTEXT_HANDLE * authContextHandle
)
{
    HRESULT hr = S_OK;
    BYTE* pDecryptedAuthContext = NULL;
    UINT32 decryptedSize = 0;
    PUSER_BOUND_KEY_AUTH_CONTEXT_INTERNAL pInternalContext = NULL;

    //
    // Step 1: Validate input parameters
    //
    hr = ValidateAuthContextInputParameters(sessionKeyPtr, authContextBlob, authContextBlobSize, authContextHandle);
    if (FAILED(hr))
    {
        goto cleanup;
    }

    //
    // Step 2: Decrypt the auth context blob using BCrypt APIs
    //
    hr = DecryptAuthContextBlob(sessionKeyPtr, authContextBlob, authContextBlobSize, &pDecryptedAuthContext, &decryptedSize);
    if (FAILED(hr))
    {
        goto cleanup;
    }

    //
    // Step 3: Create and return auth context handle
    //
    pInternalContext = (PUSER_BOUND_KEY_AUTH_CONTEXT_INTERNAL)VengcAlloc(sizeof(USER_BOUND_KEY_AUTH_CONTEXT_INTERNAL));
    if (pInternalContext == NULL)
    {
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }

    // Store the decrypted data in the internal context
    pInternalContext->pDecryptedAuthContext = pDecryptedAuthContext;
    pInternalContext->decryptedSize = decryptedSize;

    // Return the internal context as an opaque handle
    *authContextHandle = (USER_BOUND_KEY_AUTH_CONTEXT_HANDLE)pInternalContext;

    // Clear local pointers so they won't be freed in cleanup
    pDecryptedAuthContext = NULL;
    pInternalContext = NULL;

    cleanup:
        // Clean up on failure
    if (pDecryptedAuthContext != NULL)
    {
        VengcSecureFree(pDecryptedAuthContext, decryptedSize);
    }

    if (pInternalContext != NULL)
    {
        VengcFree(pInternalContext);
    }

    return hr;
}

// Called as part of the flow when loading an existing user bound key.
// Decrypts the auth context blob provided by NGC, verifies that the keyname matches the one in the auth context blob.
HRESULT GetUserBoundKeyLoadingAuthContext(
    _In_ UINT_PTR sessionKeyPtr,
    _In_reads_bytes_(authContextBlobSize) const void* authContextBlob, // auth context generated as part of RequestCreateAsync 
    _In_ UINT32 authContextBlobSize,
    _Out_ USER_BOUND_KEY_AUTH_CONTEXT_HANDLE * authContextHandle
)
{
    UNREFERENCED_PARAMETER(sessionKeyPtr);
    UNREFERENCED_PARAMETER(authContextBlob);
    UNREFERENCED_PARAMETER(authContextBlobSize);
    UNREFERENCED_PARAMETER(authContextHandle);
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
    _In_ BYTE * pDecryptedAuthContext,
    _In_ UINT32 decryptedSize,
    _In_ const USER_BOUND_KEY_AUTH_CONTEXT_PROPERTY * propCacheConfig
)
{
    // The decrypted auth context is a NCRYPT_NGC_AUTHORIZATION_CONTEXT structure
    // that contains structured data

    // Ensure we have enough data for the basic structure
    if (decryptedSize < sizeof(NCRYPT_NGC_AUTHORIZATION_CONTEXT))
    {
        return E_INVALIDARG;
    }

    // Cast to the authorization context structure
    PNCRYPT_NGC_AUTHORIZATION_CONTEXT authCtx = (PNCRYPT_NGC_AUTHORIZATION_CONTEXT)pDecryptedAuthContext;

    // Verify the structure size field
    if (authCtx->structSize != sizeof(NCRYPT_NGC_AUTHORIZATION_CONTEXT))
    {
        return E_INVALIDARG;
    }

    // Verify the key name length is valid
    if (authCtx->keyNameLength == 0 || authCtx->keyNameLength > sizeof(authCtx->keyName))
    {
        return E_INVALIDARG;
    }

    // Extract the key name from the structure
    SIZE_T keyNameChars = authCtx->keyNameLength / sizeof(WCHAR);

    // Ensure the key name is null-terminated within the allocated space
    WCHAR tempKeyName[NGC_KEY_NAME_BUFFER_SIZE + 1] = {0}; // +1 for safety
    SIZE_T charsToCopy = min(keyNameChars, NGC_KEY_NAME_BUFFER_SIZE);
    memcpy(tempKeyName, authCtx->keyName, charsToCopy * sizeof(WCHAR));
    tempKeyName[charsToCopy] = L'\0'; // Ensure null termination

    // Compare the extracted key name with the provided key name
    if (wcscmp(keyName, tempKeyName) != 0)
    {
        // Key names don't match - this auth context is for a different key
        return E_ACCESSDENIED;
    }

    // Key name verification successful - we can proceed with the rest of the auth context data
    // Verify the secure id is owner id state
    if (!authCtx->isSecureIdOwnerId)
    {
        // This authorization context is not for the secure ID owner
        return E_ACCESSDENIED;
    }

    // Verify cache_config for authCtx == the one from caller.
    if (authCtx->cacheConfig.cacheType == ((KEY_CREDENTIAL_CACHE_CONFIG*)propCacheConfig->value)->cacheType)
    {
        // This appears to be a standard Hello key cache configuration
        // which is not allowed for user bound keys
        return E_INVALIDARG;
    }

    // Validate public key bytes
    UINT32 ngcPublicKeySize = authCtx->trustletSignedPublicKeyByteCount;

    // Validate the public key size is reasonable
    if (ngcPublicKeySize < NGC_PUBLIC_KEY_MIN_SIZE || ngcPublicKeySize > NGC_PUBLIC_KEY_MAX_SIZE) // Allow for signature overhead
    {
        return E_INVALIDARG;
    }

    // Verify the public key data doesn't exceed the buffer
    SIZE_T maxTrustletDataSize = decryptedSize - offsetof(NCRYPT_NGC_AUTHORIZATION_CONTEXT, trustletSignedPublicKey);
    if (ngcPublicKeySize > maxTrustletDataSize)
    {
        return E_INVALIDARG;
    }

    return S_OK;
}

// Verifies that the keyname matches the one in the auth context blob, 
// and validates cacheConfig, IsSecureIdOwnerId, publicKeyBytes
HRESULT ValidateUserBoundKeyAuthContext(
    _In_ PCWSTR keyName,
    _In_ USER_BOUND_KEY_AUTH_CONTEXT_HANDLE authContextHandle,
    _In_ UINT32 count,
    _In_reads_(count) const USER_BOUND_KEY_AUTH_CONTEXT_PROPERTY * values
)
{
    HRESULT hr = S_OK;
    PUSER_BOUND_KEY_AUTH_CONTEXT_INTERNAL pInternalContext = NULL;

    //
    // Step 1: Validate input parameters
    //
    if (keyName == NULL || authContextHandle == NULL || (count > 0 && values == NULL))
    {
        return E_INVALIDARG;
    }

    // Cast the handle to internal context
    pInternalContext = (PUSER_BOUND_KEY_AUTH_CONTEXT_INTERNAL)authContextHandle;
    if (pInternalContext->pDecryptedAuthContext == NULL || pInternalContext->decryptedSize == 0)
    {
        return E_INVALIDARG;
    }

    // If count is 0, nothing to validate
    if (count == 0)
    {
        return S_OK;
    }

    //
    // Step 2: Verify keyName, isSecureIdOwnerId and cacheConfig
    //
    hr = ValidateAuthorizationContext(keyName, pInternalContext->pDecryptedAuthContext, pInternalContext->decryptedSize, values);
    if (FAILED(hr))
    {
        goto cleanup;
    }

    cleanup:
    return hr;
}

//
// Step 4: Extract NGC public key and perform key establishment
//
static HRESULT
PerformECDHKeyEstablishment(
    _In_ PNCRYPT_NGC_AUTHORIZATION_CONTEXT authCtx,
    _In_ UINT32 decryptedSize,
    _Out_ BCRYPT_ALG_HANDLE * phEccAlg,
    _Out_ BCRYPT_KEY_HANDLE * pEcdhKeyPair,
    _Out_ BCRYPT_KEY_HANDLE * pHelloPublicKeyHandle,
    _Out_ BCRYPT_SECRET_HANDLE * pEcdhSecret,
    _Out_ ULONG * pDerivedKeySize,
    _Out_ BYTE * * ppSharedSecret
)
{
    HRESULT hr = S_OK;
    BCRYPT_ALG_HANDLE hEccAlg = NULL;
    BCRYPT_KEY_HANDLE ecdhKeyPair = NULL;
    BCRYPT_KEY_HANDLE helloPublicKeyHandle = NULL;
    BCRYPT_SECRET_HANDLE ecdhSecret = NULL;
    ULONG derivedKeySize = 0;

    // Declare all variables at the beginning to avoid goto initialization issues
    BYTE* pNgcPublicKeyData = NULL;
    UINT32 ngcPublicKeySize = 0;
    SIZE_T maxTrustletDataSize = 0;
    BYTE* pSharedSecret = NULL;

    // Extract NGC public key from the authorization context structure
    // The trustlet signed public key data is directly available in the structure
    // ECDH Key Exchange with NGC Public Key

    pNgcPublicKeyData = authCtx->trustletSignedPublicKey;
    ngcPublicKeySize = authCtx->trustletSignedPublicKeyByteCount;

    // Validate the public key size is reasonable
    if (ngcPublicKeySize < NGC_PUBLIC_KEY_MIN_SIZE || ngcPublicKeySize > NGC_PUBLIC_KEY_MAX_SIZE) // Allow for signature overhead
    {
        hr = E_INVALIDARG;
        goto cleanup;
    }

    // Verify the public key data doesn't exceed the buffer
    maxTrustletDataSize = decryptedSize - offsetof(NCRYPT_NGC_AUTHORIZATION_CONTEXT, trustletSignedPublicKey);
    if (ngcPublicKeySize > maxTrustletDataSize)
    {
        hr = E_INVALIDARG;
        goto cleanup;
    }

    // Open ECDH P-384 algorithm provider 
    // TODO: Need to support other algorithms: ECDH P-256
    // Do we need to pass the algorithm from the glue here?
    hr = HRESULT_FROM_NT(BCryptOpenAlgorithmProvider(
        &hEccAlg,
        BCRYPT_ECDH_P384_ALGORITHM,
        NULL,
        0));
    if (FAILED(hr))
    {
        goto cleanup;
    }

    // Generate enclave key pair for ECDH (384-bit for P-384)
    hr = HRESULT_FROM_NT(BCryptGenerateKeyPair(hEccAlg, &ecdhKeyPair, ECDH_P384_KEY_SIZE_BITS, 0));
    if (FAILED(hr))
    {
        goto cleanup;
    }

    // Finalize the enclave key pair
    hr = HRESULT_FROM_NT(BCryptFinalizeKeyPair(ecdhKeyPair, 0));
    if (FAILED(hr))
    {
        goto cleanup;
    }

    // Import NGC public key for ECDH
    // Note: The NGC public key data is in pNgcPublicKeyData with size ngcPublicKeySize
    // This assumes the key is in BCRYPT_ECCPUBLIC_BLOB format
    hr = HRESULT_FROM_NT(BCryptImportKeyPair(
        hEccAlg,
        NULL,
        BCRYPT_ECCPUBLIC_BLOB,
        &helloPublicKeyHandle,
        pNgcPublicKeyData,
        ngcPublicKeySize,
        0));
    if (FAILED(hr))
    {
        goto cleanup;
    }

    // Derive a key to use as a Key-Encryption-Key (KEK)
    // Perform ECDH secret agreement
    hr = HRESULT_FROM_NT(BCryptSecretAgreement(ecdhKeyPair, helloPublicKeyHandle, &ecdhSecret, 0));
    if (FAILED(hr))
    {
        goto cleanup;
    }

    // Derive the shared secret
    hr = HRESULT_FROM_NT(BCryptDeriveKey(ecdhSecret, BCRYPT_KDF_RAW_SECRET, NULL, NULL, 0, &derivedKeySize, 0));
    if (FAILED(hr))
    {
        goto cleanup;
    }

    // Allocate buffer for the actual shared secret
    pSharedSecret = (BYTE*)VengcAlloc(derivedKeySize);
    if (pSharedSecret == NULL)
    {
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }

    // Actually derive the shared secret into the buffer
    hr = HRESULT_FROM_NT(BCryptDeriveKey(ecdhSecret, BCRYPT_KDF_RAW_SECRET, NULL, pSharedSecret, derivedKeySize, &derivedKeySize, 0));
    if (FAILED(hr))
    {
        VengcSecureFree(pSharedSecret, derivedKeySize);
        goto cleanup;
    }

    // Success - transfer ownership to caller
    *phEccAlg = hEccAlg;
    *pEcdhKeyPair = ecdhKeyPair;
    *pHelloPublicKeyHandle = helloPublicKeyHandle;
    *pEcdhSecret = ecdhSecret;
    *pDerivedKeySize = derivedKeySize;
    *ppSharedSecret = pSharedSecret;

    hEccAlg = NULL;
    ecdhKeyPair = NULL;
    helloPublicKeyHandle = NULL;
    ecdhSecret = NULL;

    cleanup:
    if (ecdhSecret != NULL)
    {
        BCryptDestroySecret(ecdhSecret);
    }

    if (helloPublicKeyHandle != NULL)
    {
        BCryptDestroyKey(helloPublicKeyHandle);
    }

    if (ecdhKeyPair != NULL)
    {
        BCryptDestroyKey(ecdhKeyPair);
    }

    if (hEccAlg != NULL)
    {
        BCryptCloseAlgorithmProvider(hEccAlg, 0);
    }

    return hr;
}

//
// Step 5: Compute KEK from the established shared secret
//
static HRESULT
ComputeKEKFromSharedSecret(
    _In_ BCRYPT_ALG_HANDLE hEccAlg,
    _In_ BCRYPT_KEY_HANDLE ecdhKeyPair,
    _In_ BYTE * pSharedSecret,
    _In_ ULONG derivedKeySize,
    _Out_ BCRYPT_KEY_HANDLE * phDerivedKey,
    _Out_ PUCHAR * ppEnclavePublicKeyBlob,
    _Out_ ULONG * pEnclavePublicKeyBlobSize
)
{
    HRESULT hr = S_OK;
    BCRYPT_KEY_HANDLE hDerivedKey = NULL;
    PUCHAR pEnclavePublicKeyBlob = NULL;
    ULONG enclavePublicKeyBlobSize = 0;

    // Generate symmetric key from the shared secret for KEK derivation
    hr = HRESULT_FROM_NT(BCryptGenerateSymmetricKey(
        hEccAlg,                    // Algorithm handle (reuse ECC algorithm handle)
        &hDerivedKey,               // Output key handle
        NULL,                       // Key object buffer (auto-allocated)
        0,                          // Key object buffer size
        pSharedSecret,              // Key material (shared secret)
        derivedKeySize,             // Key material size
        0));                        // Flags
    if (FAILED(hr))
    {
        goto cleanup;
    }

    // Export enclave public key for later use
    hr = HRESULT_FROM_NT(BCryptExportKey(
        ecdhKeyPair,
        NULL,
        BCRYPT_ECCPUBLIC_BLOB,
        NULL,
        0,
        &enclavePublicKeyBlobSize,
        0));
    if (FAILED(hr))
    {
        goto cleanup;
    }

    pEnclavePublicKeyBlob = (PUCHAR)VengcAlloc(enclavePublicKeyBlobSize);
    if (pEnclavePublicKeyBlob == NULL)
    {
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }

    hr = HRESULT_FROM_NT(BCryptExportKey(
        ecdhKeyPair,
        NULL,
        BCRYPT_ECCPUBLIC_BLOB,
        pEnclavePublicKeyBlob,
        enclavePublicKeyBlobSize,
        &enclavePublicKeyBlobSize,
        0));
    if (FAILED(hr))
    {
        goto cleanup;
    }

    // Success - transfer ownership to caller
    *phDerivedKey = hDerivedKey;
    *ppEnclavePublicKeyBlob = pEnclavePublicKeyBlob;
    *pEnclavePublicKeyBlobSize = enclavePublicKeyBlobSize;

    hDerivedKey = NULL;
    pEnclavePublicKeyBlob = NULL;

    cleanup:
    if (hDerivedKey != NULL)
    {
        BCryptDestroyKey(hDerivedKey);
    }

    if (pEnclavePublicKeyBlob != NULL)
    {
        VengcFree(pEnclavePublicKeyBlob);
    }

    return hr;
}

//
// Step 5: Create bound key structure from encrypted components
//
static HRESULT
CreateBoundKeyStructure(
    _In_ PUCHAR pEnclavePublicKeyBlob,
    _In_ ULONG enclavePublicKeyBlobSize,
    _In_ BYTE * nonce,
    _In_ BYTE * pEncryptedUserKey,
    _In_ ULONG bytesEncrypted,
    _In_ BYTE * authTag,
    _Out_ void** ppBoundKey,
    _Out_ UINT32 * pBoundKeySize
)
{
    HRESULT hr = S_OK;
    void* pBoundKey = NULL;

    // Declare all variables at the beginning to avoid goto initialization issues
    UINT32 actualBoundKeySize = 0;
    BYTE* pCurrentPos = NULL;

    // Create the bound key structure:
    // [enclave public key blob size (4 bytes)]
    // [enclave public key blob]
    // [nonce (12 bytes)]
    // [encrypted user key size (4 bytes)]
    // [encrypted user key data]
    // [authentication tag (16 bytes)]

    actualBoundKeySize = sizeof(UINT32) + enclavePublicKeyBlobSize +
        AES_GCM_NONCE_SIZE + sizeof(UINT32) +
        bytesEncrypted + AES_GCM_TAG_SIZE;

    pBoundKey = VengcAlloc(actualBoundKeySize);
    if (pBoundKey == NULL)
    {
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }

    pCurrentPos = (BYTE*)pBoundKey;

    // Store enclave public key blob size
    *((UINT32*)pCurrentPos) = enclavePublicKeyBlobSize;
    pCurrentPos += sizeof(UINT32);

    // Store enclave public key blob
    memcpy(pCurrentPos, pEnclavePublicKeyBlob, enclavePublicKeyBlobSize);
    pCurrentPos += enclavePublicKeyBlobSize;

    // Store nonce
    memcpy(pCurrentPos, nonce, AES_GCM_NONCE_SIZE);
    pCurrentPos += AES_GCM_NONCE_SIZE;

    // Store encrypted user key size
    *((UINT32*)pCurrentPos) = bytesEncrypted;
    pCurrentPos += sizeof(UINT32);

    // Store encrypted user key data
    memcpy(pCurrentPos, pEncryptedUserKey, bytesEncrypted);
    pCurrentPos += bytesEncrypted;

    // Store authentication tag
    memcpy(pCurrentPos, authTag, AES_GCM_TAG_SIZE);

    // Success - transfer ownership to caller
    *ppBoundKey = pBoundKey;
    *pBoundKeySize = actualBoundKeySize;
    pBoundKey = NULL; // Transfer ownership

    cleanup:
    if (pBoundKey != NULL)
    {
        VengcFree(pBoundKey);
    }

    return hr;
}

//
// Step 4: Encrypt user key using the KEK with AES-GCM
//
static HRESULT
EncryptUserKeyWithKEK(
    _In_ BCRYPT_KEY_HANDLE hDerivedKey,
    _In_ const void* userKey,
    _In_ UINT32 userKeySize,
    _In_ PUCHAR pEnclavePublicKeyBlob,
    _In_ ULONG enclavePublicKeyBlobSize,
    _Out_ void** ppBoundKey,
    _Out_ UINT32 * pBoundKeySize
)
{
    HRESULT hr = S_OK;
    void* pBoundKey = NULL;
    BYTE* pEncryptedUserKey = NULL;
    UINT32 encryptedUserKeySize = 0;  // Initialize to 0

    // Generate nonce using BCryptGenRandom
    // Declare all variables at the beginning to avoid goto initialization issues
    BYTE nonce[AES_GCM_NONCE_SIZE];
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BYTE authTag[AES_GCM_TAG_SIZE];
    ULONG bytesEncrypted = 0;

    // Generate nonce using BCryptGenRandom
    hr = BCryptGenRandom(NULL, nonce, AES_GCM_NONCE_SIZE, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (FAILED(hr))
    {
        goto cleanup;
    }

    // Set up AES-GCM authentication info
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = nonce;
    authInfo.cbNonce = AES_GCM_NONCE_SIZE;
    authInfo.cbTag = AES_GCM_TAG_SIZE;

    // Allocate buffer for encrypted user key
    encryptedUserKeySize = userKeySize;
    pEncryptedUserKey = (BYTE*)VengcAlloc(encryptedUserKeySize);
    if (pEncryptedUserKey == NULL)
    {
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }

    authInfo.pbTag = authTag;

    // Call BCryptEncrypt on the userKey using hDerivedKey
    hr = BCryptEncrypt(
        hDerivedKey,
        (PUCHAR)userKey,
        userKeySize,
        &authInfo,
        NULL,  // No IV for GCM (nonce is in authInfo)
        0,
        pEncryptedUserKey,
        encryptedUserKeySize,
        &bytesEncrypted,
        0
    );

    if (FAILED(hr))
    {
        goto cleanup;
    }

    // Create bound key structure from encrypted components
    hr = CreateBoundKeyStructure(
        pEnclavePublicKeyBlob,
        enclavePublicKeyBlobSize,
        nonce,
        pEncryptedUserKey,
        bytesEncrypted,
        authTag,
        ppBoundKey,
        pBoundKeySize
    );
    if (FAILED(hr))
    {
        goto cleanup;
    }

    cleanup:
    if (pEncryptedUserKey != NULL)
    {
        VengcSecureFree(pEncryptedUserKey, encryptedUserKeySize);
    }

    if (pBoundKey != NULL)
    {
        VengcFree(pBoundKey);
    }

    return hr;
}

// Performs key establishment using the enclave key handle provided, along with the
// corresponding key from the NGC side (present in the auth context blob).
// Computes the key encryption key (KEK) for the user bound key.
// Encrypt the user key and produce material to save to disk
HRESULT ProtectUserBoundKey(
    _In_ USER_BOUND_KEY_AUTH_CONTEXT_HANDLE authContext,
    _In_reads_bytes_(userKeySize) const void* userKey,
    _In_ UINT32 userKeySize,
    _Outptr_result_buffer_(*boundKeySize) void** boundKey,
    _Inout_ UINT32 * boundKeySize
)
{
    HRESULT hr = S_OK;
    PUSER_BOUND_KEY_AUTH_CONTEXT_INTERNAL pInternalContext = NULL;
    PNCRYPT_NGC_AUTHORIZATION_CONTEXT authCtx = NULL;

    // ECDH key establishment variables
    BCRYPT_ALG_HANDLE hEccAlg = NULL;
    BCRYPT_KEY_HANDLE ecdhKeyPair = NULL;
    BCRYPT_KEY_HANDLE helloPublicKeyHandle = NULL;
    BCRYPT_SECRET_HANDLE ecdhSecret = NULL;
    PUCHAR pEnclavePublicKeyBlob = NULL;
    ULONG enclavePublicKeyBlobSize = 0;
    BYTE* pSharedSecret = NULL;
    ULONG derivedKeySize = 0;
    BCRYPT_KEY_HANDLE hDerivedKey = NULL;

    void* pBoundKey = NULL;

    //
    // Step 1: Validate input parameters
    //
    if (authContext == NULL || userKey == NULL || userKeySize == 0 || boundKey == NULL || boundKeySize == NULL)
    {
        return E_INVALIDARG;
    }

    // Cast the handle to internal context
    pInternalContext = (PUSER_BOUND_KEY_AUTH_CONTEXT_INTERNAL)authContext;
    if (pInternalContext->pDecryptedAuthContext == NULL || pInternalContext->decryptedSize == 0)
    {
        return E_INVALIDARG;
    }

    // Typecast the decrypted auth context to the authorization context structure
    authCtx = (PNCRYPT_NGC_AUTHORIZATION_CONTEXT)pInternalContext->pDecryptedAuthContext;

    //
    // Step 2: Extract NGC public key and perform key establishment
    //
    hr = PerformECDHKeyEstablishment(authCtx, pInternalContext->decryptedSize, &hEccAlg, &ecdhKeyPair, &helloPublicKeyHandle, &ecdhSecret, &derivedKeySize, &pSharedSecret);
    if (FAILED(hr))
    {
        goto cleanup;
    }

    //
    // Step 3: Compute KEK (hDerivedKey)
    //
    hr = ComputeKEKFromSharedSecret(hEccAlg, ecdhKeyPair, pSharedSecret, derivedKeySize, &hDerivedKey, &pEnclavePublicKeyBlob, &enclavePublicKeyBlobSize);
    if (FAILED(hr))
    {
        goto cleanup;
    }

    // Note: We are discarding the ECDH private key! (explicit for clarity)
    // 
    //  This means we can never re-materialize the KEK here, we need Hello to do that for us
    //  using the Hello private key (and the ephemeral public key)
    if (ecdhKeyPair != NULL)
    {
        BCryptDestroyKey(ecdhKeyPair);
        ecdhKeyPair = NULL;
    }

    // Clean up ECDH handles (keep shared secret and KEK for encryption)
    if (ecdhSecret != NULL)
    {
        BCryptDestroySecret(ecdhSecret);
        ecdhSecret = NULL;
    }

    if (helloPublicKeyHandle != NULL)
    {
        BCryptDestroyKey(helloPublicKeyHandle);
        helloPublicKeyHandle = NULL;
    }

    //
    // Step 4: Encrypt the user key using the KEK
    //
    hr = EncryptUserKeyWithKEK(hDerivedKey, userKey, userKeySize, pEnclavePublicKeyBlob, enclavePublicKeyBlobSize, &pBoundKey, boundKeySize);
    if (FAILED(hr))
    {
        goto cleanup;
    }

    // Return the bound key
    *boundKey = pBoundKey;
    pBoundKey = NULL; // Transfer ownership

    cleanup:
        // Clean up ECDH key establishment resources
    if (pBoundKey != NULL)
    {
        VengcFree(pBoundKey);
    }

    if (pSharedSecret != NULL)
    {
        VengcSecureFree(pSharedSecret, derivedKeySize);
    }

    if (hDerivedKey != NULL)
    {
        BCryptDestroyKey(hDerivedKey);
    }

    if (pEnclavePublicKeyBlob != NULL)
    {
        VengcFree(pEnclavePublicKeyBlob);
    }

    if (ecdhSecret != NULL)
    {
        BCryptDestroySecret(ecdhSecret);
    }

    if (helloPublicKeyHandle != NULL)
    {
        BCryptDestroyKey(helloPublicKeyHandle);
    }

    if (ecdhKeyPair != NULL)
    {
        BCryptDestroyKey(ecdhKeyPair);
    }

    if (hEccAlg != NULL)
    {
        BCryptCloseAlgorithmProvider(hEccAlg, 0);
    }

    return hr;
}

// Decrypt the user key from material from disk
HRESULT UnprotectUserBoundKey(
    _In_ USER_BOUND_KEY_AUTH_CONTEXT_HANDLE authContext,
    _In_reads_bytes_(secretSize) const void* secret,
    _In_ UINT32 secretSize,
    _In_reads_bytes_(boundKeySize) const void* boundKey,
    _In_ UINT32 boundKeySize,
    _Outptr_result_buffer_(*userKeySize) void** userKey,
    _Inout_ UINT32 * userKeySize
)
{
    UNREFERENCED_PARAMETER(authContext);
    UNREFERENCED_PARAMETER(secret);
    UNREFERENCED_PARAMETER(secretSize);
    UNREFERENCED_PARAMETER(boundKey);
    UNREFERENCED_PARAMETER(boundKeySize);
    UNREFERENCED_PARAMETER(userKey);
    UNREFERENCED_PARAMETER(userKeySize);
    return S_OK;
}
