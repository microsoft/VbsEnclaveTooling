// Copyright (c) Microsoft Corporation.
//

#include "pch.h"
#include "vengcdll.h"  // Use quotes for local header
#include "vtl0_functions.vtl1.h"  // Add this include for debug_print

// Forward declarations for NGC types
// Structure to return values for NCRYPT_NGC_AUTHORIZATION_CONTEXT_PROPERTY
typedef struct _NCRYPT_NGC_AUTHORIZATION_CONTEXT{
    DWORD structSize;
    BOOL isSecureIdOwnerId;
    KEY_CREDENTIAL_CACHE_CONFIG cacheConfig;
    DWORD keyNameLength;
    WCHAR keyName[KCM_KEY_NAME_BUFFER_SIZE];
    DWORD publicKeyByteCount;
    BYTE publicKey[1];
} NCRYPT_NGC_AUTHORIZATION_CONTEXT, * PNCRYPT_NGC_AUTHORIZATION_CONTEXT;

// Use HeapAlloc/HeapFree instead of malloc/free for VTL1 compatibility
#define VengcAlloc(size) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (size))
#define VengcFree(ptr) HeapFree(GetProcessHeap(), 0, (ptr))

// Custom secure free function for VTL1 context
void VengcSecureFree(void* ptr, SIZE_T size)
{
    if (ptr && size > 0)
    {
        // Zero the memory before freeing
        RtlSecureZeroMemory(ptr, size);
        VengcFree(ptr);
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

// Internal structure to hold decrypted auth context data
typedef struct _USER_BOUND_KEY_AUTH_CONTEXT_INTERNAL {
    BYTE* pDecryptedAuthContext;
    UINT32 decryptedSize;
} USER_BOUND_KEY_AUTH_CONTEXT_INTERNAL, * PUSER_BOUND_KEY_AUTH_CONTEXT_INTERNAL;

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
    _In_ UINT32* reportSize,
    _In_ UINT_PTR* sessionKeyPtr
)
{
    if (challenge == NULL || challengeSize == 0)
    {
        return E_INVALIDARG;
    }

    if (report == NULL || reportSize == NULL || sessionKeyPtr == NULL)
    {
        return E_POINTER;
    }

    // Initialize output parameters
    *report = NULL;
    *reportSize = 0;
    *sessionKeyPtr = 0;

    return S_OK;
}

//
// Step 2: Generate session key for encryption
//
static HRESULT
GenerateSessionKey(
    _In_ UINT32 sessionKeySize,
    _Out_ BCRYPT_KEY_HANDLE* phSessionKey,
    _Out_ PUCHAR* ppSessionKeyBytes
)
{
    veil::vtl1::vtl0_functions::debug_print("DEBUG: GenerateSessionKey - Function entered");

    HRESULT hr = S_OK;
    PUCHAR pSessionKeyBytes = NULL;
    BCRYPT_KEY_HANDLE hSessionKey = NULL;

    // Allocate memory for key bytes
    veil::vtl1::vtl0_functions::debug_print("DEBUG: GenerateSessionKey - Allocating memory for key bytes");
    pSessionKeyBytes = (PUCHAR)VengcAlloc(sessionKeySize);
    if (pSessionKeyBytes == NULL)
    {
        veil::vtl1::vtl0_functions::debug_print("DEBUG: GenerateSessionKey - Memory allocation failed");
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }
    veil::vtl1::vtl0_functions::debug_print("DEBUG: GenerateSessionKey - Memory allocation succeeded");

    // Generate cryptographically secure random key bytes
    veil::vtl1::vtl0_functions::debug_print("DEBUG: GenerateSessionKey - Calling BCryptGenRandom");
    hr = HRESULT_FROM_NT(BCryptGenRandom(NULL, pSessionKeyBytes, sessionKeySize, BCRYPT_USE_SYSTEM_PREFERRED_RNG));
    if (FAILED(hr))
    {
        veil::vtl1::vtl0_functions::debug_print("DEBUG: GenerateSessionKey - BCryptGenRandom failed");
        goto cleanup;
    }
    veil::vtl1::vtl0_functions::debug_print("DEBUG: GenerateSessionKey - BCryptGenRandom succeeded");

    // Create symmetric key from the generated bytes using AES-GCM algorithm
    veil::vtl1::vtl0_functions::debug_print("DEBUG: GenerateSessionKey - Calling BCryptGenerateSymmetricKey");
    hr = HRESULT_FROM_NT(BCryptGenerateSymmetricKey(BCRYPT_AES_GCM_ALG_HANDLE, &hSessionKey, NULL, 0, pSessionKeyBytes, sessionKeySize, 0));
    if (FAILED(hr))
    {
        veil::vtl1::vtl0_functions::debug_print("DEBUG: GenerateSessionKey - BCryptGenerateSymmetricKey failed");
        goto cleanup;
    }
    veil::vtl1::vtl0_functions::debug_print("DEBUG: GenerateSessionKey - BCryptGenerateSymmetricKey succeeded");

    // Success - transfer ownership to caller
    *phSessionKey = hSessionKey;
    *ppSessionKeyBytes = pSessionKeyBytes;
    hSessionKey = NULL;
    pSessionKeyBytes = NULL;

    veil::vtl1::vtl0_functions::debug_print("DEBUG: GenerateSessionKey - Function completed successfully");

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
    _Out_ UINT32* pAttestationReportSize,
    _Out_ PS_TRUSTLET_TKSESSION_ID* pSessionId
)
{
    veil::vtl1::vtl0_functions::debug_print("DEBUG: GenerateAttestationReport - Function entered");

    HRESULT hr = S_OK;
    void* pAttestationReport = NULL;
    UINT32 attestationReportSize = 0;

    // Declare all variables at the beginning to avoid goto initialization issues
    BYTE enclaveData[ENCLAVE_REPORT_DATA_LENGTH] = {0};
    SIZE_T copyLen = 0;
    UINT32 tempReportSize = 0;
    BYTE attestationVector[Vtl1MutualAuth::AttestationData::c_attestationDataVectorSize];
    Vtl1MutualAuth::AttestationData attestationData {};
    Vtl1MutualAuth::SessionChallenge sessionChallenge {};

    // Parse the NGC session challenge using SessionChallenge directly
    veil::vtl1::vtl0_functions::debug_print("DEBUG: GenerateAttestationReport - Parsing NGC session challenge");
    hr = Vtl1MutualAuth::SessionChallenge::FromVector((const BYTE*)challenge, challengeSize, &sessionChallenge);
    if (FAILED(hr))
    {
        veil::vtl1::vtl0_functions::debug_print("DEBUG: GenerateAttestationReport - SessionChallenge::FromVector failed");
        goto cleanup;
    }
    veil::vtl1::vtl0_functions::debug_print("DEBUG: GenerateAttestationReport - SessionChallenge::FromVector succeeded");

    // Create AttestationData using the standard Vtl1MutualAuth structure
    veil::vtl1::vtl0_functions::debug_print("DEBUG: GenerateAttestationReport - Creating AttestationData structure");

    // Copy challenge bytes (guaranteed to be exactly 24 bytes)
    memcpy(attestationData.challenge, sessionChallenge.challenge, sizeof(attestationData.challenge));

    // Copy session key as symmetric secret (both are 32 bytes)
    // static_assert(sizeof(attestationData.symmetricSecret) == sessionKeySize, "Session key size mismatch");
    memcpy(attestationData.symmetricSecret, pSessionKeyBytes, sessionKeySize);

    veil::vtl1::vtl0_functions::debug_print("DEBUG: GenerateAttestationReport - Converting AttestationData to vector");
    hr = attestationData.ToVector(attestationVector);
    if (FAILED(hr))
    {
        veil::vtl1::vtl0_functions::debug_print("DEBUG: GenerateAttestationReport - AttestationData::ToVector failed");
        goto cleanup;
    }
    veil::vtl1::vtl0_functions::debug_print("DEBUG: GenerateAttestationReport - AttestationData::ToVector succeeded");

    // Calculate copy length and prepare enclaveData buffer
    copyLen = Vtl1MutualAuth::AttestationData::c_attestationDataVectorSize < ENCLAVE_REPORT_DATA_LENGTH ? 
              Vtl1MutualAuth::AttestationData::c_attestationDataVectorSize : ENCLAVE_REPORT_DATA_LENGTH;
    memcpy(enclaveData, attestationVector, copyLen);

    // Debug print: Display all computed sizes so far
    veil::vtl1::vtl0_functions::debug_print("DEBUG: GenerateAttestationReport - Computed sizes: challengeSize=%u, sessionKeySize=%u, attestationVectorSize=%u", 
                                            challengeSize, sessionKeySize, (UINT32)Vtl1MutualAuth::AttestationData::c_attestationDataVectorSize);

    // Call Windows enclave attestation API to get size
    veil::vtl1::vtl0_functions::debug_print("DEBUG: GenerateAttestationReport - Calling EnclaveGetAttestationReport (size query)");
    hr = EnclaveGetAttestationReport(enclaveData, NULL, 0, &tempReportSize);
    if (FAILED(hr))
    {
        veil::vtl1::vtl0_functions::debug_print("DEBUG: GenerateAttestationReport - EnclaveGetAttestationReport (size query) failed");
        goto cleanup;
    }
    veil::vtl1::vtl0_functions::debug_print("DEBUG: GenerateAttestationReport - EnclaveGetAttestationReport (size query) succeeded");

    attestationReportSize = tempReportSize;

    // Allocate buffer for the actual attestation report
    veil::vtl1::vtl0_functions::debug_print("DEBUG: GenerateAttestationReport - Allocating buffer for attestation report");
    pAttestationReport = VengcAlloc(attestationReportSize);
    if (pAttestationReport == NULL)
    {
        veil::vtl1::vtl0_functions::debug_print("DEBUG: GenerateAttestationReport - Buffer allocation failed");
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }

    // Get the actual attestation report
    veil::vtl1::vtl0_functions::debug_print("DEBUG: GenerateAttestationReport - Calling EnclaveGetAttestationReport (actual call)");
    hr = EnclaveGetAttestationReport(enclaveData, pAttestationReport, attestationReportSize, &tempReportSize);
    if (FAILED(hr))
    {
        veil::vtl1::vtl0_functions::debug_print("DEBUG: GenerateAttestationReport - EnclaveGetAttestationReport (actual call) failed");
        goto cleanup;
    }
    veil::vtl1::vtl0_functions::debug_print("DEBUG: GenerateAttestationReport - EnclaveGetAttestationReport (actual call) succeeded");

    // Success - transfer ownership to caller
    *ppAttestationReport = pAttestationReport;
    *pAttestationReportSize = attestationReportSize;
    *pSessionId = sessionChallenge.sessionId;
    pAttestationReport = NULL;

    veil::vtl1::vtl0_functions::debug_print("DEBUG: GenerateAttestationReport - Function completed successfully");

    cleanup:
        // Clean up allocated resources
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
    _Out_ UINT32* pEncryptedReportSize
)
{
    veil::vtl1::vtl0_functions::debug_print("DEBUG: EncryptAttestationReport - Function entered");

    HRESULT hr = S_OK;
    void* pEncryptedReport = NULL;
    UINT32 encryptedReportSize = 0;

    // Set up trustlet binding data
    veil::vtl1::vtl0_functions::debug_print("DEBUG: EncryptAttestationReport - Setting up trustlet binding data");
    TRUSTLET_BINDING_DATA trustletData;
    trustletData.TrustletIdentity = TRUSTLETIDENTITY_KCM;
    trustletData.TrustletSessionId = sessionId;
    trustletData.TrustletSvn = 0;
    trustletData.Reserved1 = 0;
    trustletData.Reserved2 = 0;

    // Get the required buffer size for encrypted data
    veil::vtl1::vtl0_functions::debug_print("DEBUG: EncryptAttestationReport - Calling EnclaveEncryptDataForTrustlet (size query)");
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
        veil::vtl1::vtl0_functions::debug_print("DEBUG: EncryptAttestationReport - EnclaveEncryptDataForTrustlet (size query) failed");
        goto cleanup;
    }
    veil::vtl1::vtl0_functions::debug_print("DEBUG: EncryptAttestationReport - EnclaveEncryptDataForTrustlet (size query) succeeded");

    encryptedReportSize = tempEncryptedSize;
    veil::vtl1::vtl0_functions::debug_print("DEBUG: EncryptAttestationReport - Allocating buffer for encrypted report");
    pEncryptedReport = VengcAlloc(encryptedReportSize);
    if (pEncryptedReport == NULL)
    {
        veil::vtl1::vtl0_functions::debug_print("DEBUG: EncryptAttestationReport - Buffer allocation failed");
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }

    // Perform the actual encryption
    veil::vtl1::vtl0_functions::debug_print("DEBUG: EncryptAttestationReport - Calling EnclaveEncryptDataForTrustlet (actual call)");
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
        veil::vtl1::vtl0_functions::debug_print("DEBUG: EncryptAttestationReport - EnclaveEncryptDataForTrustlet (actual call) failed");
        goto cleanup;
    }
    veil::vtl1::vtl0_functions::debug_print("DEBUG: EncryptAttestationReport - EnclaveEncryptDataForTrustlet (actual call) succeeded");

    // Update the actual encrypted size
    encryptedReportSize = tempEncryptedSize;

    // Success - transfer ownership to caller
    *ppEncryptedReport = pEncryptedReport;
    *pEncryptedReportSize = encryptedReportSize;
    pEncryptedReport = NULL;

    veil::vtl1::vtl0_functions::debug_print("DEBUG: EncryptAttestationReport - Function completed successfully");

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
    _Out_ UINT32* reportSize,
    _Out_ UINT_PTR* sessionKey
)
{
    // DEBUG: Log entry to InitializeUserBoundKeySessionInfo
    veil::vtl1::vtl0_functions::debug_print("DEBUG: InitializeUserBoundKeySessionInfo - Function entered");

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
    veil::vtl1::vtl0_functions::debug_print("DEBUG: Step 1 - Validating input parameters");
    hr = ValidateSessionInputParameters(challenge, challengeSize, report, reportSize, sessionKey);
    if (FAILED(hr))
    {
        veil::vtl1::vtl0_functions::debug_print("DEBUG: Step 1 - Input parameter validation failed");
        goto cleanup;
    }
    veil::vtl1::vtl0_functions::debug_print("DEBUG: Step 1 - Input parameter validation succeeded");

    //
    // Step 2: Generate session key for encryption
    //
    veil::vtl1::vtl0_functions::debug_print("DEBUG: Step 2 - Generating session key");
    hr = GenerateSessionKey(SESSION_KEY_SIZE, &hSessionKey, &pSessionKeyBytes);
    if (FAILED(hr))
    {
        veil::vtl1::vtl0_functions::debug_print("DEBUG: Step 2 - Generate session key failed");
        goto cleanup;
    }
    veil::vtl1::vtl0_functions::debug_print("DEBUG: Step 2 - Generate session key succeeded");

    // Store the session key handle for later use
    pSessionKey = (void*)hSessionKey;

    //
    // Step 3: Generate attestation report with session key and challenge
    //
    veil::vtl1::vtl0_functions::debug_print("DEBUG: Step 3 - Generating attestation report");
    hr = GenerateAttestationReport(challenge, challengeSize, pSessionKeyBytes, SESSION_KEY_SIZE,
                                  &pAttestationReport, &attestationReportSize, &sessionId);
    if (FAILED(hr))
    {
        veil::vtl1::vtl0_functions::debug_print("DEBUG: Step 3 - Generate attestation report failed");
        goto cleanup;
    }
    veil::vtl1::vtl0_functions::debug_print("DEBUG: Step 3 - Generate attestation report succeeded");

    //
    // Step 4: Encrypt attestation report using EnclaveEncryptDataForTrustlet
    //
    veil::vtl1::vtl0_functions::debug_print("DEBUG: Step 4 - Encrypting attestation report");
    hr = EncryptAttestationReport(pAttestationReport, attestationReportSize, sessionId,
                                 &pEncryptedReport, &encryptedReportSize);
    if (FAILED(hr))
    {
        veil::vtl1::vtl0_functions::debug_print("DEBUG: Step 4 - Encrypt attestation report failed");
        goto cleanup;
    }
    veil::vtl1::vtl0_functions::debug_print("DEBUG: Step 4 - Encrypt attestation report succeeded");

    //
    // Step 5: Return encrypted report and session key information
    //
    veil::vtl1::vtl0_functions::debug_print("DEBUG: Step 5 - Returning results");
    *report = pEncryptedReport;
    *reportSize = encryptedReportSize;
    *sessionKey = (UINT_PTR)pSessionKey;

    // Clear local pointers so they won't be freed in cleanup
    pEncryptedReport = NULL;
    pSessionKey = NULL;

    veil::vtl1::vtl0_functions::debug_print("DEBUG: InitializeUserBoundKeySessionInfo - Function completed successfully");

    cleanup:
        // Clean up on failure
    if (FAILED(hr))
    {
        veil::vtl1::vtl0_functions::debug_print("DEBUG: InitializeUserBoundKeySessionInfo - Cleanup on failure");
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

//
// Session management APIs
// Closes a user bound key session and destroys the associated BCRYPT_KEY_HANDLE
HRESULT CloseUserBoundKeySession(
    _In_ const VEINTEROP_SESSION_INFO* sessionInfo)
{
    if (sessionInfo == nullptr)
    {
        return E_INVALIDARG;
    }

    if (sessionInfo->sessionKeyPtr == 0)
    {
        return E_INVALIDARG;
    }

    BCRYPT_KEY_HANDLE hSessionKey = reinterpret_cast<BCRYPT_KEY_HANDLE>(sessionInfo->sessionKeyPtr);
    
    // Destroy the BCrypt key handle
    NTSTATUS status = BCryptDestroyKey(hSessionKey);
    if (FAILED(HRESULT_FROM_NT(status)))
    {
        return HRESULT_FROM_NT(status);
    }

    return S_OK;
}

HRESULT CloseUserBoundKeyAuthContextHandle(
    _In_ USER_BOUND_KEY_AUTH_CONTEXT_HANDLE handle)
{
    if (handle == NULL)
    {
        return E_INVALIDARG;
    }

    // Cast to internal context to access internal data
    PUSER_BOUND_KEY_AUTH_CONTEXT_INTERNAL pInternalContext = (PUSER_BOUND_KEY_AUTH_CONTEXT_INTERNAL)handle;

    // Free the internal decrypted auth context data if it exists
    if (pInternalContext->pDecryptedAuthContext != NULL && pInternalContext->decryptedSize > 0)
    {
        VengcSecureFree(pInternalContext->pDecryptedAuthContext, pInternalContext->decryptedSize);
    }

    // Free the handle memory itself
    VengcFree(handle);

    return S_OK;
}

//
// Private helper functions for GetUserBoundKeyAuthContext
//

//
// Step 1: Validate input parameters for auth context creation
//
static HRESULT
ValidateAuthContextInputParameters(
    _In_ UINT_PTR sessionKeyPtr,
    _In_ const void* authContextBlob,
    _In_ UINT32 authContextBlobSize,
    _In_ USER_BOUND_KEY_AUTH_CONTEXT_HANDLE* authContextHandle
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
    _Out_ BYTE** ppDecryptedAuthContext,
    _Out_ UINT32* pDecryptedSize
)
{
    HRESULT hr = S_OK;
    BYTE* pDecryptedAuthContext = NULL;
    UINT32 decryptedSize = 0;

    // Declare all variables at the beginning to avoid goto initialization issues
    BCRYPT_KEY_HANDLE hSessionKey = NULL;
    const UINT32 VTL1_TAG_SIZE = AES_GCM_TAG_SIZE;       // AES-GCM auth tag at end
    const ULONG64 c_responderBitFlip = 0x80000000ULL;
    UINT64 nonce = 0;
    const BYTE* pEncryptedData = NULL;
    UINT32 encryptedDataSize = 0;
    const BYTE* pAuthTag = NULL;
    BYTE nonceBuffer[AES_GCM_NONCE_SIZE] = {0}; // Fill with 0s
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    ULONG bytesDecrypted = 0;
    const ULONG64 constantTestNonce = 0x1234567890ABCDEFULL;  // Same as NgcIsoSrv.cpp

    // The auth context blob was encrypted using ClientAuth::EncryptResponse which uses
    // VTL1 mutual authentication protocol with AES-GCM format.
    // IMPORTANT: EncryptResponse (new protocol) format is: [encrypted data][16-byte auth tag]
    // The nonce is NOT stored in the encrypted blob - it must be provided separately!

    hSessionKey = (BCRYPT_KEY_HANDLE)sessionKeyPtr;
    if (hSessionKey == NULL)
    {
        hr = E_INVALIDARG;
        goto cleanup;
    }

    // For EncryptResponse format: [encrypted data][16-byte auth tag]
    if (authContextBlobSize < VTL1_TAG_SIZE)
    {
        hr = NTE_BAD_DATA;
        goto cleanup;
    }

    // For EncryptResponse, we need to reconstruct the nonce used during encryption
    // The nonce used was: requestNonce ^ c_responderBitFlip (where requestNonce was provided to EncryptResponse)
    // TEMPORARY: Use the same constant nonce as NgcIsoSrv.cpp for testing
    // TODO: Implement proper nonce sharing between encryption and decryption
    nonce = constantTestNonce ^ c_responderBitFlip;  // Apply responder bit flip as per VTL1 protocol

    // Add nonce value towards the end of the buffer (last 8 bytes)
    memcpy(&nonceBuffer[AES_GCM_NONCE_SIZE - sizeof(nonce)], &nonce, sizeof(nonce));

    // Extract components from the EncryptResponse encrypted blob
    // Format: [encrypted data][16-byte auth tag] - NO NONCE stored in blob
    pEncryptedData = (const BYTE*)authContextBlob;
    encryptedDataSize = authContextBlobSize - VTL1_TAG_SIZE;
    pAuthTag = pEncryptedData + encryptedDataSize;

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
    hr = HRESULT_FROM_NT(BCryptDecrypt(
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
    ));

    if (FAILED(hr))
    {
        goto cleanup;
    }

    decryptedSize = bytesDecrypted;

    // Debug print: Display computed sizes for decryption operation
    veil::vtl1::vtl0_functions::debug_print("DEBUG: DecryptAuthContextBlob - Computed sizes: decryptedSize=%u, encryptedDataSize=%u", decryptedSize, encryptedDataSize);

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
HRESULT GetUserBoundKeyAuthContext(
    _In_ UINT_PTR sessionKeyPtr,
    _In_reads_bytes_(authContextBlobSize) const void* authContextBlob,
    _In_ UINT32 authContextBlobSize,
    _Out_ USER_BOUND_KEY_AUTH_CONTEXT_HANDLE* authContextHandle
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

//
// Private helper functions for ValidateUserBoundKeyAuthContext
//
//
// Step 2: Verify keyName, isSecureIdOwnerId and cacheConfig
//
static HRESULT
ValidateAuthorizationContext(
    _In_ BYTE* pDecryptedAuthContext,
    _In_ UINT32 decryptedSize,
    _In_ UINT32 count,
    _In_ const USER_BOUND_KEY_AUTH_CONTEXT_PROPERTY* authctxproperties
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

    // Always verify the secure ID owner ID state
    if (!authCtx->isSecureIdOwnerId)
    {
        // This authorization context is not for the secure ID owner
        return E_ACCESSDENIED;
    }

    // Always validate public key bytes size
    UINT32 ngcPublicKeySize = authCtx->publicKeyByteCount;

    // Validate the public key size is reasonable
    if (ngcPublicKeySize < KCM_PUBLIC_KEY_MIN_SIZE)
    {
        return E_INVALIDARG;
    }

    // Verify the public key data doesn't exceed the buffer
    SIZE_T maxPublicKeySize = decryptedSize - offsetof(NCRYPT_NGC_AUTHORIZATION_CONTEXT, publicKey);
    if (ngcPublicKeySize > maxPublicKeySize)
    {
        return E_INVALIDARG;
    }

    // Loop through all provided properties and validate each one
    for (UINT32 i = 0; i < count; i++)
    {
        const USER_BOUND_KEY_AUTH_CONTEXT_PROPERTY* currentProperty = &authctxproperties[i];
        
        switch (currentProperty->name)
        {
            case UserBoundKeyAuthContextPropertyCacheConfig:
            {
                // Verify cache_config for authCtx == the one from caller
                if (currentProperty->size != sizeof(KEY_CREDENTIAL_CACHE_CONFIG) || currentProperty->value == NULL)
                {
                    return E_INVALIDARG;
                }
                
                KEY_CREDENTIAL_CACHE_CONFIG* callerCacheConfig = (KEY_CREDENTIAL_CACHE_CONFIG*)currentProperty->value;
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
    _In_ USER_BOUND_KEY_AUTH_CONTEXT_HANDLE authContextHandle,
    _In_ UINT32 count,
    _In_reads_(count) const USER_BOUND_KEY_AUTH_CONTEXT_PROPERTY* values
)
{
    HRESULT hr = S_OK;
    PUSER_BOUND_KEY_AUTH_CONTEXT_INTERNAL pInternalContext = NULL;

    //
    // Step 1: Validate input parameters
    //
    if (authContextHandle == NULL || (count > 0 && values == NULL))
    {
        return E_INVALIDARG;
    }

    // Cast the handle to internal context
    pInternalContext = (PUSER_BOUND_KEY_AUTH_CONTEXT_INTERNAL)authContextHandle;
    if (pInternalContext->pDecryptedAuthContext == NULL || pInternalContext->decryptedSize == 0)
    {
        return E_INVALIDARG;
    }

    //
    // Step 2: Verify properties against authorization context
    //
    hr = ValidateAuthorizationContext(pInternalContext->pDecryptedAuthContext, pInternalContext->decryptedSize, count, values);
    if (FAILED(hr))
    {
        goto cleanup;
    }

    cleanup:
    return hr;
}

//
// Private helper functions for ProtectUserBoundKey
//
//
// Step 2: Extract NGC public key and perform key establishment
//
static HRESULT
PerformECDHKeyEstablishment(
    _In_ PNCRYPT_NGC_AUTHORIZATION_CONTEXT authCtx,
    _In_ UINT32 decryptedSize,
    _Out_ BCRYPT_KEY_HANDLE* pEcdhKeyPair,
    _Out_ BCRYPT_KEY_HANDLE* pHelloPublicKeyHandle,
    _Out_ BCRYPT_SECRET_HANDLE* pEcdhSecret,
    _Out_ ULONG* pDerivedKeySize,
    _Out_ BYTE** ppSharedSecret
)
{
    HRESULT hr = S_OK;
    BCRYPT_KEY_HANDLE ecdhKeyPair = NULL;
    BCRYPT_KEY_HANDLE helloPublicKeyHandle = NULL;
    BCRYPT_SECRET_HANDLE ecdhSecret = NULL;
    ULONG derivedKeySize = 0;

    // Declare all variables at the beginning to avoid goto initialization issues
    BYTE* pNgcPublicKeyData = NULL;
    UINT32 ngcPublicKeySize = 0;
    SIZE_T maxTrustletDataSize = 0;
    BYTE* pSharedSecret = NULL;
    BYTE* pRawTrustletData = NULL;
    UINT32 rawTrustletDataSize = 0;
    const UINT32 EXPECTED_NONCE_SIZE = 8;


    // Extract NGC public key from the authorization context structure
    // The trustlet signed public key data contains [nonce][raw_public_key_data]
    // We need to skip the nonce part and extract the actual public key

    pRawTrustletData = authCtx->publicKey;
    rawTrustletDataSize = authCtx->publicKeyByteCount;

    // Validate the trustlet data size is reasonable
    if (rawTrustletDataSize < KCM_PUBLIC_KEY_MIN_SIZE || rawTrustletDataSize > KCM_PUBLIC_KEY_MAX_SIZE)
    {
        veil::vtl1::vtl0_functions::debug_print("DEBUG: PerformECDHKeyEstablishment - Invalid trustlet data size, expected between %u and %u bytes", KCM_PUBLIC_KEY_MIN_SIZE, KCM_PUBLIC_KEY_MAX_SIZE);
        hr = E_INVALIDARG;
        goto cleanup;
    }

    // Verify the trustlet data doesn't exceed the buffer
    maxTrustletDataSize = decryptedSize - offsetof(NCRYPT_NGC_AUTHORIZATION_CONTEXT, publicKey);
    if (rawTrustletDataSize > maxTrustletDataSize)
    {
        hr = E_INVALIDARG;
        goto cleanup;
    }

    // The publicKey format is: [nonce (usually 16 bytes)][actual public key data]
    // For P-384, we expect the nonce to be 16 bytes followed by the public key in BCRYPT_ECCPUBLIC_BLOB format
    if (rawTrustletDataSize <= EXPECTED_NONCE_SIZE)
    {
        hr = E_INVALIDARG;
        goto cleanup;
    }

    // Skip the nonce to get to the actual public key data
    pNgcPublicKeyData = pRawTrustletData + EXPECTED_NONCE_SIZE;
    ngcPublicKeySize = rawTrustletDataSize - EXPECTED_NONCE_SIZE;

    // DEBUG: Log BCryptImportKeyPair parameters
    veil::vtl1::vtl0_functions::debug_print("DEBUG: PerformECDHKeyEstablishment - Calling BCryptImportKeyPair with:");
    veil::vtl1::vtl0_functions::debug_print("DEBUG:   Algorithm: BCRYPT_ECDH_P384_ALG_HANDLE");
    veil::vtl1::vtl0_functions::debug_print("DEBUG:   Blob type: BCRYPT_ECCPUBLIC_BLOB");
    veil::vtl1::vtl0_functions::debug_print("DEBUG:   Key data size: %u bytes", ngcPublicKeySize);
    veil::vtl1::vtl0_functions::debug_print("DEBUG:   Expected P-384 public key size: %u bytes (uncompressed)", 2 * 48 + sizeof(BCRYPT_ECCKEY_BLOB));

    // Import NGC public key for ECDH
    // The public key data (after skipping header) should be in BCRYPT_ECCPUBLIC_BLOB format
    hr = HRESULT_FROM_NT(BCryptImportKeyPair(
        BCRYPT_ECDH_P384_ALG_HANDLE,
        NULL,
        BCRYPT_ECCPUBLIC_BLOB,
        &helloPublicKeyHandle,
        pNgcPublicKeyData,
        ngcPublicKeySize,
        0));

    // DEBUG: Log BCryptImportKeyPair result
    if (FAILED(hr))
    {
        veil::vtl1::vtl0_functions::debug_print("DEBUG: PerformECDHKeyEstablishment - BCryptImportKeyPair FAILED with HRESULT: 0x%08X", hr);
        goto cleanup;
    }
    else
    {
        veil::vtl1::vtl0_functions::debug_print("DEBUG: PerformECDHKeyEstablishment - BCryptImportKeyPair succeeded");
    }


    // Generate enclave key pair for ECDH (384-bit for P-384)
    hr = HRESULT_FROM_NT(BCryptGenerateKeyPair(BCRYPT_ECDH_P384_ALG_HANDLE, &ecdhKeyPair, ECDH_P384_KEY_SIZE_BITS, 0));
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
    *pEcdhKeyPair = ecdhKeyPair;
    *pHelloPublicKeyHandle = helloPublicKeyHandle;
    *pEcdhSecret = ecdhSecret;
    *pDerivedKeySize = derivedKeySize;
    *ppSharedSecret = pSharedSecret;

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

    return hr;
}

//
// Step 3: Compute KEK from the established shared secret
//
static HRESULT
ComputeKEKFromSharedSecret(
    _In_ BCRYPT_KEY_HANDLE ecdhKeyPair,
    _In_ BYTE* pSharedSecret,
    _In_ ULONG derivedKeySize,
    _Out_ BCRYPT_KEY_HANDLE* phDerivedKey,
    _Out_ PUCHAR* ppEnclavePublicKeyBlob,
    _Out_ ULONG* pEnclavePublicKeyBlobSize
)
{
    HRESULT hr = S_OK;
    BCRYPT_KEY_HANDLE hDerivedKey = NULL;
    PUCHAR pEnclavePublicKeyBlob = NULL;
    ULONG enclavePublicKeyBlobSize = 0;

    // Generate symmetric key from the shared secret for KEK derivation
    hr = HRESULT_FROM_NT(BCryptGenerateSymmetricKey(
        BCRYPT_AES_GCM_ALG_HANDLE,// Algorithm handle (reuse ECC algorithm handle)
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
// Step 4.1: Create bound key structure from encrypted components
//
static HRESULT
CreateBoundKeyStructure(
    _In_ PUCHAR pEnclavePublicKeyBlob,
    _In_ ULONG enclavePublicKeyBlobSize,
    _In_ BYTE* nonce,
    _In_ BYTE* pEncryptedUserKey,
    _In_ ULONG bytesEncrypted,
    _In_ BYTE* authTag,
    _Out_ void** ppBoundKey,
    _Out_ UINT32* pBoundKeySize
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
    _Out_ UINT32* pBoundKeySize
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
    hr = HRESULT_FROM_NT(BCryptGenRandom(NULL, nonce, AES_GCM_NONCE_SIZE, BCRYPT_USE_SYSTEM_PREFERRED_RNG));
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
    hr = HRESULT_FROM_NT(BCryptEncrypt(
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
    ));

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
    _Inout_ UINT32* boundKeySize
)
{
    HRESULT hr = S_OK;
    PUSER_BOUND_KEY_AUTH_CONTEXT_INTERNAL pInternalContext = NULL;
    PNCRYPT_NGC_AUTHORIZATION_CONTEXT authCtx = NULL;

    // ECDH key establishment variables
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
    if (authContext == NULL || 
        userKey == NULL || 
        userKeySize == 0 || 
        boundKey == NULL || 
        boundKeySize == NULL)
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
    hr = PerformECDHKeyEstablishment(authCtx, pInternalContext->decryptedSize, &ecdhKeyPair, &helloPublicKeyHandle, &ecdhSecret, &derivedKeySize, &pSharedSecret);
    if (FAILED(hr))
    {
        goto cleanup;
    }

    //
    // Step 3: Compute KEK (hDerivedKey)
    //
    hr = ComputeKEKFromSharedSecret(ecdhKeyPair, pSharedSecret, derivedKeySize, &hDerivedKey, &pEnclavePublicKeyBlob, &enclavePublicKeyBlobSize);
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

    return hr;
}

//
// Creates an encrypted NGC request for DeriveSharedSecret using session information and ephemeral public key bytes
HRESULT CreateEncryptedRequestForDeriveSharedSecret(
    _Inout_ VEINTEROP_SESSION_INFO* sessionInfo,
    _In_reads_bytes_(keyNameSize) const void* keyName,
    _In_ UINT32 keyNameSize,
    _In_reads_bytes_(publicKeyBytesSize) const void* publicKeyBytes,
    _In_ UINT32 publicKeyBytesSize,
    _Outptr_result_buffer_(*encryptedRequestSize) void** encryptedRequest,
    _Out_ UINT32* encryptedRequestSize
)
{
    veil::vtl1::vtl0_functions::debug_print("DEBUG: CreateEncryptedRequestForDeriveSharedSecret - Function entered");

    HRESULT hr = S_OK;
    void* pEncryptedRequest = NULL;
    UINT32 totalEncryptedSize = 0;
    BYTE* pPlaintextBuffer = NULL;
    UINT32 plaintextSize = 0;
    BYTE* pCiphertextBuffer = NULL;
    BYTE* pEncryptedData = NULL;
    ULONG bytesEncrypted = 0;

    // Declare all variables at the beginning to avoid goto initialization issues
    const char header[] = "NgcReq"; // 7 bytes including null terminator
    const UINT32 OPERATION_DERIVE_SHARED_SECRET = 2;
    BYTE* pCurrentPos = NULL;
    ULONG64 requestNonce = 0;
    ULONG64 nonce = 0;
    BYTE nonceBuffer[AES_GCM_NONCE_SIZE] = {0};
    BYTE authTag[AES_GCM_TAG_SIZE] = {0};
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_KEY_HANDLE sessionKey = NULL;

    //
    // Step 1: Validate input parameters
    //
    veil::vtl1::vtl0_functions::debug_print("DEBUG: CreateEncryptedRequestForDeriveSharedSecret - Step 1: Validating input parameters");
    if (sessionInfo == NULL ||
        sessionInfo->sessionKeyPtr == 0 ||
        keyName == NULL || 
        keyNameSize == 0 || 
        publicKeyBytes == NULL || 
        publicKeyBytesSize == 0 ||
        encryptedRequest == NULL || 
        encryptedRequestSize == NULL)
    {
        veil::vtl1::vtl0_functions::debug_print("DEBUG: CreateEncryptedRequestForDeriveSharedSecret - Invalid input parameters");
        hr = E_INVALIDARG;
        goto cleanup;
    }

    // Initialize output parameters
    *encryptedRequest = NULL;
    *encryptedRequestSize = 0;

    veil::vtl1::vtl0_functions::debug_print("DEBUG: CreateEncryptedRequestForDeriveSharedSecret - Input validation completed");
    veil::vtl1::vtl0_functions::debug_print("DEBUG: CreateEncryptedRequestForDeriveSharedSecret - sessionKeyPtr: 0x%p", (void*)sessionInfo->sessionKeyPtr);
    veil::vtl1::vtl0_functions::debug_print("DEBUG: CreateEncryptedRequestForDeriveSharedSecret - current sessionNonce: %llu", sessionInfo->sessionNonce);
    veil::vtl1::vtl0_functions::debug_print("DEBUG: CreateEncryptedRequestForDeriveSharedSecret - keyNameSize: %u", keyNameSize);
    veil::vtl1::vtl0_functions::debug_print("DEBUG: CreateEncryptedRequestForDeriveSharedSecret - publicKeyBytesSize: %u", publicKeyBytesSize);

    //
    // Step 2: Construct NGC request structure
    //
    veil::vtl1::vtl0_functions::debug_print("DEBUG: CreateEncryptedRequestForDeriveSharedSecret - Step 2: Constructing NGC request");

    // NGC request format with 7-byte header:
    // [7 bytes: header "NgcReq" including null terminator]
    // [4 bytes: operation type (DeriveSharedSecret = 2)]
    // [4 bytes: key name size]
    // [key name data]
    // [4 bytes: public key size]
    // [public key data]

    // Calculate total plaintext size
    plaintextSize = sizeof(header) +   // 7-byte header including null terminator
        sizeof(UINT32) +    // operation type
        sizeof(UINT32) +    // key name size
        keyNameSize +       // key name data
        sizeof(UINT32) +    // public key size
        publicKeyBytesSize; // public key data

    // Allocate plaintext buffer
    pPlaintextBuffer = (BYTE*)VengcAlloc(plaintextSize);
    if (pPlaintextBuffer == NULL)
    {
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }

    // Build the plaintext buffer
    pCurrentPos = pPlaintextBuffer;

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

    veil::vtl1::vtl0_functions::debug_print("DEBUG: CreateEncryptedRequestForDeriveSharedSecret - Constructed plaintext, size: %u", plaintextSize);

    //
    // Step 3: Handle nonce manipulation to prevent reuse
    //
    veil::vtl1::vtl0_functions::debug_print("DEBUG: CreateEncryptedRequestForDeriveSharedSecret - Step 3: Handling nonce manipulation");

    // Handle nonce manipulation to prevent reuse
    nonce = sessionInfo->sessionNonce;
    if (nonce > 0)
    {
        // This nonce is already used once. We should increment it to avoid reuse.
        nonce++;
    }

    nonce = InterlockedIncrement64(reinterpret_cast<LONG64*>(&requestNonce));

    if (nonce >= Vtl1MutualAuth::c_maxRequestNonce)
    {
        hr = HRESULT_FROM_WIN32(ERROR_TOO_MANY_SECRETS);
        goto cleanup;
    }

    veil::vtl1::vtl0_functions::debug_print("DEBUG: CreateEncryptedRequestForDeriveSharedSecret - Using nonce: %llu", nonce);

    // Create nonce buffer manually (instead of using crypto utility)
    memcpy(&nonceBuffer[AES_GCM_NONCE_SIZE - sizeof(nonce)], &nonce, sizeof(nonce));

    //
    // Step 4: Encrypt the NGC request using BCrypt directly
    //
    veil::vtl1::vtl0_functions::debug_print("DEBUG: CreateEncryptedRequestForDeriveSharedSecret - Step 4: Encrypting NGC request");

    // Set up AES-GCM authentication info
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = nonceBuffer;
    authInfo.cbNonce = AES_GCM_NONCE_SIZE;
    authInfo.pbTag = authTag;
    authInfo.cbTag = AES_GCM_TAG_SIZE;

    // Get session key handle
    sessionKey = reinterpret_cast<BCRYPT_KEY_HANDLE>(sessionInfo->sessionKeyPtr);

    // Allocate buffer for encrypted data
    pEncryptedData = (BYTE*)VengcAlloc(plaintextSize);
    if (pEncryptedData == NULL)
    {
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }

    // DEBUG: Print nonce and tag before BCryptEncrypt
    {
        char nonceHexStr[AES_GCM_NONCE_SIZE * 2 + 1] = {0};
        char tagHexStr[AES_GCM_TAG_SIZE * 2 + 1] = {0};

        // Convert nonce to hex string
        for (UINT32 i = 0; i < AES_GCM_NONCE_SIZE; i++)
        {
            sprintf_s(&nonceHexStr[i * 2], 3, "%02X", nonceBuffer[i]);
        }

        // Convert tag to hex string (should be zeros before encryption)
        for (UINT32 i = 0; i < AES_GCM_TAG_SIZE; i++)
        {
            sprintf_s(&tagHexStr[i * 2], 3, "%02X", authTag[i]);
        }

        veil::vtl1::vtl0_functions::debug_print("DEBUG: CreateEncryptedRequestForDeriveSharedSecret - BEFORE BCryptEncrypt - Nonce (hex): %s", nonceHexStr);
        veil::vtl1::vtl0_functions::debug_print("DEBUG: CreateEncryptedRequestForDeriveSharedSecret - BEFORE BCryptEncrypt - Auth Tag (hex): %s", tagHexStr);
    }

    // Encrypt the plaintext using BCrypt
    // In AES-GCM ciphertext and plaintext lengths are the same
    hr = HRESULT_FROM_NT(BCryptEncrypt(
        sessionKey,
        pPlaintextBuffer,
        plaintextSize,
        &authInfo,
        NULL,  // No IV for GCM (nonce is in authInfo)
        0,
        pEncryptedData,
        plaintextSize,
        &bytesEncrypted,
        0
    ));

    // DEBUG: Print nonce and tag after BCryptEncrypt
    {
        char nonceHexStr[AES_GCM_NONCE_SIZE * 2 + 1] = {0};
        char tagHexStr[AES_GCM_TAG_SIZE * 2 + 1] = {0};

        // Convert nonce to hex string
        for (UINT32 i = 0; i < AES_GCM_NONCE_SIZE; i++)
        {
            sprintf_s(&nonceHexStr[i * 2], 3, "%02X", nonceBuffer[i]);
        }

        // Convert tag to hex string (should contain auth tag after encryption)
        for (UINT32 i = 0; i < AES_GCM_TAG_SIZE; i++)
        {
            sprintf_s(&tagHexStr[i * 2], 3, "%02X", authTag[i]);
        }

        veil::vtl1::vtl0_functions::debug_print("DEBUG: CreateEncryptedRequestForDeriveSharedSecret - AFTER BCryptEncrypt - Nonce (hex): %s", nonceHexStr);
        veil::vtl1::vtl0_functions::debug_print("DEBUG: CreateEncryptedRequestForDeriveSharedSecret - AFTER BCryptEncrypt - Auth Tag (hex): %s", tagHexStr);
    }

    if (FAILED(hr))
    {
        veil::vtl1::vtl0_functions::debug_print("DEBUG: CreateEncryptedRequestForDeriveSharedSecret - BCryptEncrypt failed");
        goto cleanup;
    }

    //
    // Step 5: Construct final encrypted request format
    //
    veil::vtl1::vtl0_functions::debug_print("DEBUG: CreateEncryptedRequestForDeriveSharedSecret - Step 5: Constructing final encrypted request");

    // Final format: [8 bytes: nonce number][encrypted data][16 bytes: auth tag]
    totalEncryptedSize = sizeof(nonce) + bytesEncrypted + AES_GCM_TAG_SIZE;

    // Allocate ciphertext buffer
    pCiphertextBuffer = (BYTE*)VengcAlloc(totalEncryptedSize);
    if (pCiphertextBuffer == NULL)
    {
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }

    // Build the ciphertext buffer
    pCurrentPos = pCiphertextBuffer;

    // Add nonce number
    memcpy(pCurrentPos, &nonce, sizeof(nonce));
    pCurrentPos += sizeof(nonce);

    // Add encrypted data
    memcpy(pCurrentPos, pEncryptedData, bytesEncrypted);
    pCurrentPos += bytesEncrypted;

    // Add authentication tag
    memcpy(pCurrentPos, authTag, AES_GCM_TAG_SIZE);

    veil::vtl1::vtl0_functions::debug_print("DEBUG: CreateEncryptedRequestForDeriveSharedSecret - Final encrypted request size: %u", totalEncryptedSize);

    //
    // Step 6: Allocate and return encrypted request, update sessionInfo
    //
    veil::vtl1::vtl0_functions::debug_print("DEBUG: CreateEncryptedRequestForDeriveSharedSecret - Step 6: Allocating output buffer and updating sessionInfo");

    pEncryptedRequest = VengcAlloc(totalEncryptedSize);
    if (pEncryptedRequest == NULL)
    {
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }

    memcpy(pEncryptedRequest, pCiphertextBuffer, totalEncryptedSize);

    // Update the session info with the new nonce value on success
    sessionInfo->sessionNonce = nonce;
    veil::vtl1::vtl0_functions::debug_print("DEBUG: CreateEncryptedRequestForDeriveSharedSecret - Updated sessionInfo->sessionNonce to: %llu", sessionInfo->sessionNonce);

    // Success - transfer ownership to caller
    *encryptedRequest = pEncryptedRequest;
    *encryptedRequestSize = totalEncryptedSize;
    pEncryptedRequest = NULL; // Transfer ownership

    veil::vtl1::vtl0_functions::debug_print("DEBUG: CreateEncryptedRequestForDeriveSharedSecret - Function completed successfully");

cleanup:
    if (pEncryptedRequest != NULL)
    {
        VengcFree(pEncryptedRequest);
    }

    if (pEncryptedData != NULL)
    {
        VengcSecureFree(pEncryptedData, plaintextSize);
    }

    if (pPlaintextBuffer != NULL)
    {
        VengcSecureFree(pPlaintextBuffer, plaintextSize);
    }

    if (pCiphertextBuffer != NULL)
    {
        VengcFree(pCiphertextBuffer);
    }

    veil::vtl1::vtl0_functions::debug_print("DEBUG: CreateEncryptedRequestForDeriveSharedSecret - Function exiting with hr: 0x%08X", hr);
    return hr;
}
//
// Private helper functions for UnprotectUserBoundKey
//

//
// Structure to hold parsed bound key components
//
typedef struct _PARSED_BOUND_KEY_COMPONENTS {
    PUCHAR pEnclavePublicKeyBlob;
    UINT32 enclavePublicKeyBlobSize;
    BYTE nonce[AES_GCM_NONCE_SIZE];
    const BYTE* pEncryptedUserKey;
    UINT32 encryptedUserKeySize;
    const BYTE* pAuthTag;
} PARSED_BOUND_KEY_COMPONENTS, *PPARSED_BOUND_KEY_COMPONENTS;

//
// Parse the bound key structure and extract all components
//
static HRESULT
ParseBoundKeyStructure(
    _In_reads_bytes_(boundKeySize) const void* boundKey,
    _In_ UINT32 boundKeySize,
    _Out_ PPARSED_BOUND_KEY_COMPONENTS pComponents
)
{
    HRESULT hr = S_OK;
    const BYTE* pCurrentPos = NULL;
    UINT32 minBoundKeySize = 0;
    UINT32 enclavePublicKeyBlobSize = 0;
    UINT32 remainingBytes = 0;

    // Initialize output structure
    RtlSecureZeroMemory(pComponents, sizeof(PARSED_BOUND_KEY_COMPONENTS));

    // Validate minimum bound key size
    minBoundKeySize = sizeof(UINT32) + sizeof(UINT32) + AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE;
    if (boundKeySize < minBoundKeySize)
    {
        veil::vtl1::vtl0_functions::debug_print("DEBUG: ParseBoundKeyStructure - Bound key too small");
        hr = NTE_BAD_DATA;
        goto cleanup;
    }

    pCurrentPos = (const BYTE*)boundKey;

    // Read enclave public key blob size
    enclavePublicKeyBlobSize = *((const UINT32*)pCurrentPos);
    pCurrentPos += sizeof(UINT32);

    // Validate enclave public key blob size
    if (enclavePublicKeyBlobSize == 0 || enclavePublicKeyBlobSize > KCM_PUBLIC_KEY_MAX_SIZE)
    {
        veil::vtl1::vtl0_functions::debug_print("DEBUG: ParseBoundKeyStructure - Invalid enclave public key blob size: %u", enclavePublicKeyBlobSize);
        hr = NTE_BAD_DATA;
        goto cleanup;
    }

    // Verify we have enough data for the public key blob
    if ((pCurrentPos - (const BYTE*)boundKey) + enclavePublicKeyBlobSize > boundKeySize)
    {
        veil::vtl1::vtl0_functions::debug_print("DEBUG: ParseBoundKeyStructure - Insufficient data for enclave public key blob");
        hr = NTE_BAD_DATA;
        goto cleanup;
    }

    // Extract and allocate enclave public key blob
    pComponents->pEnclavePublicKeyBlob = (PUCHAR)VengcAlloc(enclavePublicKeyBlobSize);
    if (pComponents->pEnclavePublicKeyBlob == NULL)
    {
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }
    memcpy(pComponents->pEnclavePublicKeyBlob, pCurrentPos, enclavePublicKeyBlobSize);
    pComponents->enclavePublicKeyBlobSize = enclavePublicKeyBlobSize;
    pCurrentPos += enclavePublicKeyBlobSize;

    // Extract nonce
    if (static_cast<UINT32>(pCurrentPos - (const BYTE*)boundKey) + AES_GCM_NONCE_SIZE > boundKeySize)
    {
        veil::vtl1::vtl0_functions::debug_print("DEBUG: ParseBoundKeyStructure - Insufficient data for nonce");
        hr = NTE_BAD_DATA;
        goto cleanup;
    }
    memcpy(pComponents->nonce, pCurrentPos, AES_GCM_NONCE_SIZE);
    pCurrentPos += AES_GCM_NONCE_SIZE;

    // Read encrypted user key size
    if ((pCurrentPos - (const BYTE*)boundKey) + sizeof(UINT32) > boundKeySize)
    {
        veil::vtl1::vtl0_functions::debug_print("DEBUG: ParseBoundKeyStructure - Insufficient data for encrypted user key size");
        hr = NTE_BAD_DATA;
        goto cleanup;
    }
    pComponents->encryptedUserKeySize = *((const UINT32*)pCurrentPos);
    pCurrentPos += sizeof(UINT32);

    // Validate encrypted user key size
    if (pComponents->encryptedUserKeySize == 0 || 
        pComponents->encryptedUserKeySize > Vtl1MutualAuth::c_maxEncryptedUserKeySize) // Reasonable upper limit
    {
        veil::vtl1::vtl0_functions::debug_print("DEBUG: ParseBoundKeyStructure - Invalid encrypted user key size: %u", pComponents->encryptedUserKeySize);
        hr = NTE_BAD_DATA;
        goto cleanup;
    }

    // Extract encrypted user key data
    if ((pCurrentPos - (const BYTE*)boundKey) + pComponents->encryptedUserKeySize + AES_GCM_TAG_SIZE > boundKeySize)
    {
        veil::vtl1::vtl0_functions::debug_print("DEBUG: ParseBoundKeyStructure - Insufficient data for encrypted user key and auth tag");
        hr = NTE_BAD_DATA;
        goto cleanup;
    }
    pComponents->pEncryptedUserKey = pCurrentPos;
    pCurrentPos += pComponents->encryptedUserKeySize;

    // Validate that we have exactly AES_GCM_TAG_SIZE bytes remaining for the authentication tag
    remainingBytes = boundKeySize - static_cast<UINT32>(pCurrentPos - (const BYTE*)boundKey);
    if (remainingBytes != AES_GCM_TAG_SIZE)
    {
        hr = NTE_BAD_DATA;
        goto cleanup;
    }

    // Extract authentication tag - now we know we have exactly the right amount of data
    pComponents->pAuthTag = pCurrentPos;

    veil::vtl1::vtl0_functions::debug_print("DEBUG: ParseBoundKeyStructure - Bound key parsed successfully: enclave key size=%u, encrypted user key size=%u", 
                                            pComponents->enclavePublicKeyBlobSize, pComponents->encryptedUserKeySize);

cleanup:
    if (FAILED(hr) && pComponents->pEnclavePublicKeyBlob != NULL)
    {
        VengcFree(pComponents->pEnclavePublicKeyBlob);
        pComponents->pEnclavePublicKeyBlob = NULL;
    }

    return hr;
}

//
// Cleanup function for parsed bound key components
//
static void
CleanupParsedBoundKeyComponents(
    _Inout_ PPARSED_BOUND_KEY_COMPONENTS pComponents
)
{
    if (pComponents != NULL && pComponents->pEnclavePublicKeyBlob != NULL)
    {
        VengcFree(pComponents->pEnclavePublicKeyBlob);
        pComponents->pEnclavePublicKeyBlob = NULL;
    }
}

//
// Step 2: Decrypt the auth context blob using BCrypt APIs
//
static HRESULT
DecryptAndUntagSecret(
    _In_ UINT_PTR sessionKeyPtr,
    _In_ const void* secretBlob,
    _In_ UINT32 secretBlobSize,
    _Out_ BYTE** ppDecryptedSecret,
    _Out_ UINT32* pDecryptedSize,
    _In_ ULONG64 nonceNumber
)
{
    HRESULT hr = S_OK;
    BYTE* pDecryptedSecret = NULL;
    UINT32 decryptedSize = 0;

    // Declare all variables at the beginning to avoid goto initialization issues
    BCRYPT_KEY_HANDLE hSessionKey = NULL;
    const UINT32 VTL1_TAG_SIZE = AES_GCM_TAG_SIZE;       // AES-GCM auth tag at end
    const ULONG64 c_responderBitFlip = 0x80000000;
    const BYTE* pEncryptedData = NULL;
    UINT32 encryptedDataSize = 0;
    const BYTE* pAuthTag = NULL;
    BYTE nonceBuffer[AES_GCM_NONCE_SIZE] = {0}; // Fill with 0s
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    ULONG bytesDecrypted = 0;
    ULONG64 nonce = 0;

    // The auth context blob was encrypted using ClientAuth::EncryptResponse which uses
    // VTL1 mutual authentication protocol with AES-GCM format.
    // IMPORTANT: EncryptResponse (new protocol) format is: [encrypted data][16-byte auth tag]
    // The nonce is NOT stored in the encrypted blob - it must be provided separately!

    hSessionKey = (BCRYPT_KEY_HANDLE)sessionKeyPtr;
    if (hSessionKey == NULL)
    {
        hr = E_INVALIDARG;
        goto cleanup;
    }

    // For EncryptResponse format: [encrypted data][16-byte auth tag]
    if (secretBlobSize < VTL1_TAG_SIZE)
    {
        hr = NTE_BAD_DATA;
        goto cleanup;
    }

    nonce = nonceNumber ^ c_responderBitFlip;  // Apply responder bit flip as per VTL1 protocol

    // Create nonce buffer manually (instead of using crypto utility)
    memcpy(&nonceBuffer[AES_GCM_NONCE_SIZE - sizeof(nonce)], &nonce, sizeof(nonce));

    // Hex-dump the secret blob for debugging
    {
        // Use dynamic allocation instead of VLA to fix C2131 error
        size_t hexStrSize = secretBlobSize * 2 + 1;
        std::unique_ptr<char[]> secretHexStr(new char[hexStrSize]);
        memset(secretHexStr.get(), 0, hexStrSize);
        
        for (UINT32 i = 0; i < secretBlobSize; i++)
        {
            sprintf_s(&secretHexStr[i * 2], 3, "%02X", ((const BYTE*)secretBlob)[i]);
        }
        veil::vtl1::vtl0_functions::debug_print("DEBUG: DecryptAndUntagSecret - Encrypted response from DSS (hex): %s", secretHexStr.get());
    }

    // Extract components from the EncryptResponse encrypted blob
    // Format: [encrypted data][16-byte auth tag] - NO NONCE stored in blob
    pEncryptedData = (const BYTE*)secretBlob;
    encryptedDataSize = secretBlobSize - VTL1_TAG_SIZE;
    pAuthTag = pEncryptedData + encryptedDataSize;

    // DEBUG: Print nonce and tag in hex string format
    {
        char nonceHexStr[AES_GCM_NONCE_SIZE * 2 + 1] = {0};
        char tagHexStr[AES_GCM_TAG_SIZE * 2 + 1] = {0};

        // Convert nonce to hex string
        for (UINT32 i = 0; i < AES_GCM_NONCE_SIZE; i++)
        {
            sprintf_s(&nonceHexStr[i * 2], 3, "%02X", nonceBuffer[i]);
        }

        // Convert tag to hex string
        for (UINT32 i = 0; i < AES_GCM_TAG_SIZE; i++)
        {
            sprintf_s(&tagHexStr[i * 2], 3, "%02X", pAuthTag[i]);
        }

        veil::vtl1::vtl0_functions::debug_print("DEBUG: DecryptAndUntagSecret - Nonce (hex): %s", nonceHexStr);
        veil::vtl1::vtl0_functions::debug_print("DEBUG: DecryptAndUntagSecret - Auth Tag (hex): %s", tagHexStr);
    }

    // Set up AES-GCM authentication info for VTL1 format
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = nonceBuffer;
    authInfo.cbNonce = AES_GCM_NONCE_SIZE;
    authInfo.pbTag = (PUCHAR)pAuthTag;
    authInfo.cbTag = VTL1_TAG_SIZE;

    // Allocate buffer for decrypted data
    pDecryptedSecret = (BYTE*)VengcAlloc(encryptedDataSize);
    if (pDecryptedSecret == NULL)
    {
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }

    // Perform AES-GCM decryption using VTL1 format
    hr = HRESULT_FROM_NT(BCryptDecrypt(
        hSessionKey,
        (PUCHAR)pEncryptedData,
        encryptedDataSize,
        &authInfo,
        NULL,  // No IV for GCM (nonce is in authInfo)
        0,
        pDecryptedSecret,
        encryptedDataSize,
        &bytesDecrypted,
        0
    ));

    if (FAILED(hr))
    {
        goto cleanup;
    }

    decryptedSize = bytesDecrypted;

    // Debug print: Display computed sizes for decryption operation
    veil::vtl1::vtl0_functions::debug_print("DEBUG: DecryptAndUntagSecret - Computed sizes: decryptedSize=%u, encryptedDataSize=%u", decryptedSize, encryptedDataSize);

    if (pDecryptedSecret == NULL || decryptedSize == 0)
    {
        hr = E_UNEXPECTED;
        goto cleanup;
    }

    // Success - transfer ownership to caller
    *ppDecryptedSecret = pDecryptedSecret;
    *pDecryptedSize = decryptedSize;
    pDecryptedSecret = NULL;

    cleanup:
    if (pDecryptedSecret != NULL)
    {
        VengcSecureFree(pDecryptedSecret, decryptedSize);
    }

    return hr;
}

// Decrypt the user key from material from disk
HRESULT UnprotectUserBoundKey(
    _In_ const VEINTEROP_SESSION_INFO* sessionInfo,
    _In_ USER_BOUND_KEY_AUTH_CONTEXT_HANDLE /*authContext*/,
    _In_reads_bytes_(sessionEncryptedDerivedSecretSize) const void* sessionEncryptedDerivedSecret,
    _In_ UINT32 sessionEncryptedDerivedSecretSize,
    _In_reads_bytes_(encryptedUserBoundKeySize) const void* encryptedUserBoundKey,
    _In_ UINT32 encryptedUserBoundKeySize,
    _Outptr_result_buffer_(*userKeySize) void** userKey,
    _Inout_ UINT32* userKeySize
)
{
    veil::vtl1::vtl0_functions::debug_print("DEBUG: UnprotectUserBoundKey - Function entered");

    HRESULT hr = S_OK;

    // Declare all variables at the beginning to avoid goto initialization issues
    PARSED_BOUND_KEY_COMPONENTS boundKeyComponents = {0};
    BCRYPT_KEY_HANDLE ecdhKeyPair = NULL;
    BCRYPT_SECRET_HANDLE ecdhSecret = NULL;
    ULONG derivedKeySize = 0;
    BYTE* pSharedSecret = NULL;
    BCRYPT_KEY_HANDLE hDerivedKey = NULL;
    BYTE* pDecryptedUserKey = NULL;
    ULONG bytesDecrypted = 0;
    void* pOutputUserKey = NULL;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BYTE* pDecryptedSecret = NULL;
    UINT32 decryptedSecretSize = 0;

    //
    // Step 1: Validate input parameters
    //
    veil::vtl1::vtl0_functions::debug_print("DEBUG: UnprotectUserBoundKey - Step 1: Validating input parameters");
    if (sessionInfo == NULL ||
        sessionInfo->sessionKeyPtr == 0 ||
        sessionEncryptedDerivedSecret == NULL ||
        sessionEncryptedDerivedSecretSize == 0 ||
        encryptedUserBoundKey == NULL || 
        encryptedUserBoundKeySize == 0 || 
        userKey == NULL || 
        userKeySize == NULL)
    {
        hr = E_INVALIDARG;
        goto cleanup;
    }

    //
    // Step 2: Parse the bound key structure
    //
    veil::vtl1::vtl0_functions::debug_print("DEBUG: UnprotectUserBoundKey - Step 2: Parsing bound key structure");
    hr = ParseBoundKeyStructure(encryptedUserBoundKey, encryptedUserBoundKeySize, &boundKeyComponents);
    if (FAILED(hr))
    {
        goto cleanup;
    }

    //
    // Step 2.5: Decrypt the secret using session key and nonce
    //
    veil::vtl1::vtl0_functions::debug_print("DEBUG: UnprotectUserBoundKey - Step 2.5: Decrypting secret using DecryptAndUntagSecret");
    hr = DecryptAndUntagSecret(sessionInfo->sessionKeyPtr, sessionEncryptedDerivedSecret, sessionEncryptedDerivedSecretSize, &pDecryptedSecret, &decryptedSecretSize, sessionInfo->sessionNonce);
    if (FAILED(hr))
    {
        veil::vtl1::vtl0_functions::debug_print("DEBUG: UnprotectUserBoundKey - DecryptAuthContextBlob failed: 0x%08X", hr);
        goto cleanup;
    }
    veil::vtl1::vtl0_functions::debug_print("DEBUG: UnprotectUserBoundKey - DecryptAuthContextBlob succeeded, decrypted secret size: %u", decryptedSecretSize);

    //
    // Step 3: Use the decrypted secret to recreate the KEK
    //
    veil::vtl1::vtl0_functions::debug_print("DEBUG: UnprotectUserBoundKey - Step 3: Using decrypted secret to recreate KEK");

    // The decrypted secret parameter contains the shared secret that was derived during key creation
    // We use this directly to create the KEK, bypassing the ECDH computation
    derivedKeySize = decryptedSecretSize;
    pSharedSecret = (BYTE*)VengcAlloc(derivedKeySize);
    if (pSharedSecret == NULL)
    {
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }
    memcpy(pSharedSecret, pDecryptedSecret, decryptedSecretSize);

    //
    // Step 4: Generate KEK using the shared secret as key material
    //
    veil::vtl1::vtl0_functions::debug_print("DEBUG: UnprotectUserBoundKey - Step 4: Generating KEK from shared secret");
    hr = HRESULT_FROM_NT(BCryptGenerateSymmetricKey(
        BCRYPT_AES_GCM_ALG_HANDLE,
        &hDerivedKey,
        NULL,
        0,
        pSharedSecret,
        derivedKeySize,
        0));
    if (FAILED(hr))
    {
        veil::vtl1::vtl0_functions::debug_print("DEBUG: UnprotectUserBoundKey - BCryptGenerateSymmetricKey failed: 0x%08X", hr);
        goto cleanup;
    }

    //
    // Step 5: Decrypt the user key using AES-GCM
    //
    veil::vtl1::vtl0_functions::debug_print("DEBUG: UnprotectUserBoundKey - Step 5: Decrypting user key");
    
    // Allocate buffer for decrypted user key
    pDecryptedUserKey = (BYTE*)VengcAlloc(boundKeyComponents.encryptedUserKeySize);
    if (pDecryptedUserKey == NULL)
    {
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }

    // Set up AES-GCM authentication info
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = boundKeyComponents.nonce;
    authInfo.cbNonce = AES_GCM_NONCE_SIZE;
    authInfo.pbTag = (PUCHAR)boundKeyComponents.pAuthTag;
    authInfo.cbTag = AES_GCM_TAG_SIZE;

    // Perform AES-GCM decryption
    hr = HRESULT_FROM_NT(BCryptDecrypt(
        hDerivedKey,
        (PUCHAR)boundKeyComponents.pEncryptedUserKey,
        boundKeyComponents.encryptedUserKeySize,
        &authInfo,
        NULL,  // No IV for GCM (nonce is in authInfo)
        0,
        pDecryptedUserKey,
        boundKeyComponents.encryptedUserKeySize,
        &bytesDecrypted,
        0
    ));

    if (FAILED(hr))
    {
        veil::vtl1::vtl0_functions::debug_print("DEBUG: UnprotectUserBoundKey - BCryptDecrypt failed: 0x%08X", hr);
        goto cleanup;
    }

    veil::vtl1::vtl0_functions::debug_print("DEBUG: UnprotectUserBoundKey - Decryption successful, decrypted %u bytes", bytesDecrypted);

    //
    // Step 6: Return the decrypted user key
    //
    veil::vtl1::vtl0_functions::debug_print("DEBUG: UnprotectUserBoundKey - Step 6: Returning decrypted user key");
    
    // Allocate output buffer using HeapAlloc (caller will free with HeapFree)
    pOutputUserKey = VengcAlloc(bytesDecrypted);
    if (pOutputUserKey == NULL)
    {
        hr = E_OUTOFMEMORY;
        goto cleanup;
    }

    memcpy(pOutputUserKey, pDecryptedUserKey, bytesDecrypted);

    // Success - transfer ownership to caller
    *userKey = pOutputUserKey;
    *userKeySize = bytesDecrypted;
    pOutputUserKey = NULL; // Transfer ownership

    veil::vtl1::vtl0_functions::debug_print("DEBUG: UnprotectUserBoundKey - Function completed successfully");

cleanup:
    // Clean up parsed bound key components
    CleanupParsedBoundKeyComponents(&boundKeyComponents);

    // Clean up allocated resources
    if (pDecryptedSecret != NULL)
    {
        VengcSecureFree(pDecryptedSecret, decryptedSecretSize);
    }

    if (pSharedSecret != NULL)
    {
        VengcSecureFree(pSharedSecret, derivedKeySize);
    }

    if (hDerivedKey != NULL)
    {
        BCryptDestroyKey(hDerivedKey);
    }

    if (ecdhKeyPair != NULL)
    {
        BCryptDestroyKey(ecdhKeyPair);
    }

    if (ecdhSecret != NULL)
    {
        BCryptDestroySecret(ecdhSecret);
    }

    if (pDecryptedUserKey != NULL)
    {
        VengcSecureFree(pDecryptedUserKey, boundKeyComponents.encryptedUserKeySize);
    }

    if (pOutputUserKey != NULL)
    {
        VengcFree(pOutputUserKey);
    }

    return hr;
}
