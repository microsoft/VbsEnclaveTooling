#include "pch.h"

#define VEIL_IMPLEMENTATION

#include <VbsEnclave\Enclave\Implementations.h>
#include "crypto.vtl1.h"
#include "utils.vtl1.h"
#include "vengcdll.h" // OS APIs
#include "userboundkey.any.h"
#include "userboundkey.vtl1.h" // Function declarations
#include "vtl0_functions.vtl1.h"

namespace veil_abi::VTL1_Declarations
{
DeveloperTypes::attestationReportAndSessionKeyPtr userboundkey_get_attestation_report(_In_ const std::vector<std::uint8_t>& challenge)
{
    // DEBUG: Log that the enclave function has been called
    veil::vtl1::vtl0_functions::debug_print(L"DEBUG: userboundkey_get_attestation_report called - enclave function started");
    
    // DEBUG: Add hex dump of the challenge buffer
    std::wstring challengeHex = L"DEBUG: Challenge buffer (size=" + std::to_wstring(challenge.size()) + L"): ";
    for (size_t i = 0; i < challenge.size() && i < 64; ++i) { // Limit to first 64 bytes to avoid excessive output
        wchar_t hexByte[4];
        swprintf_s(hexByte, L"%02X ", challenge[i]);
        challengeHex += hexByte;
    }
    if (challenge.size() > 64) {
        challengeHex += L"... (truncated)";
    }
    veil::vtl1::vtl0_functions::debug_print(challengeHex.c_str());
    
    uint8_t* reportPtr = nullptr;
    void* tempReportPtr = nullptr; // Temporary variable of type void*
    size_t reportSize = 0;

    VEINTEROP_SESSION_INFO sessionInfo = {};

    // DEBUG: Log before calling InitializeUserBoundKeySessionInfo
    veil::vtl1::vtl0_functions::debug_print(L"DEBUG: About to call InitializeUserBoundKeySessionInfo");

    THROW_IF_FAILED(InitializeUserBoundKeySessionInfo(
        const_cast<uint8_t*>(challenge.data()),
        static_cast<UINT32>(challenge.size()),
        &tempReportPtr,
        reinterpret_cast<UINT32*>(&reportSize),
        &sessionInfo)); // OS CALL

    // DEBUG: Log after InitializeUserBoundKeySessionInfo completes
    veil::vtl1::vtl0_functions::debug_print(L"DEBUG: InitializeUserBoundKeySessionInfo completed successfully");

    reportPtr = static_cast<uint8_t*>(tempReportPtr); // Cast back to uint8_t*
    std::vector<uint8_t> report(reportPtr, reportPtr + reportSize);
    
    HeapFree(GetProcessHeap(), 0, reportPtr);

    // DEBUG: Log before returning
    veil::vtl1::vtl0_functions::debug_print(L"DEBUG: userboundkey_get_attestation_report returning successfully");

    return DeveloperTypes::attestationReportAndSessionKeyPtr {std::move(report), static_cast<std::uintptr_t>(sessionInfo.sessionKeyPtr)};
}
}

namespace veil::vtl1::implementation::userboundkey::callouts
{
    DeveloperTypes::authContextBlobAndSessionInfo userboundkey_establish_session_for_create_callback(
        _In_ const void* enclave, 
        _In_ const std::wstring& key_name, 
        _In_ const uintptr_t ecdh_protocol, 
        _In_ const std::wstring& message, 
        _In_ const uintptr_t window_id, 
        _In_ const DeveloperTypes::keyCredentialCacheConfig& cache_config)
    {
        return veil_abi::VTL0_Callbacks::userboundkey_establish_session_for_create_callback(
            reinterpret_cast<uintptr_t>(enclave),
            key_name,
            ecdh_protocol,
            message,
            window_id,
            cache_config);
    }

    DeveloperTypes::credentialAndFormattedKeyNameAndSessionInfo userboundkey_establish_session_for_load_callback(
        _In_ const void* enclave,
        _In_ const std::wstring& key_name, 
        _In_ const std::vector<std::uint8_t>& public_key, 
        _In_ const std::wstring& message, 
        _In_ const uintptr_t window_id)
    {
        return veil_abi::VTL0_Callbacks::userboundkey_establish_session_for_load_callback(
            reinterpret_cast<uintptr_t>(enclave),
            key_name,
            public_key,
            message,
            window_id);
    }

    // New function to extract secret and authorization context from credential
    DeveloperTypes::secretAndAuthorizationContext userboundkey_get_secret_and_authorizationcontext_from_credential_callback(
        _In_ const std::vector<std::uint8_t>& credential_vector,
        _In_ const std::vector<std::uint8_t>& public_key,
        _In_ const std::wstring& message,
        _In_ const uintptr_t window_id)
    {
        return veil_abi::VTL0_Callbacks::userboundkey_get_secret_and_authorizationcontext_from_credential_callback(
            credential_vector,
            public_key,
            message,
            window_id);
    }
}

namespace veil::vtl1::userboundkey
{
// Helper function to convert KEY_CREDENTIAL_CACHE_CONFIG to DeveloperTypes::keyCredentialCacheConfig
DeveloperTypes::keyCredentialCacheConfig ConvertToDeveloperType(const KEY_CREDENTIAL_CACHE_CONFIG& cacheConfig)
{
    DeveloperTypes::keyCredentialCacheConfig devType;
    devType.cacheOption = cacheConfig.cacheType;
    devType.cacheTimeoutInSeconds = cacheConfig.cacheTimeout;
    devType.cacheUsageCount = cacheConfig.cacheCallCount;
    return devType;
}

// Helper function to convert DeveloperTypes::sessionInfo to VEINTEROP_SESSION_INFO
VEINTEROP_SESSION_INFO ConvertToVeinteropSessionInfo(const DeveloperTypes::sessionInfo& sessionInfo)
{
    VEINTEROP_SESSION_INFO veinteropSessionInfo;
    veinteropSessionInfo.sessionKeyPtr = sessionInfo.sessionKeyPtr;
    veinteropSessionInfo.sessionNonce = sessionInfo.sessionNonce;
    return veinteropSessionInfo;
}

// Helper function to convert VEINTEROP_SESSION_INFO back to DeveloperTypes::sessionInfo
DeveloperTypes::sessionInfo ConvertFromVeinteropSessionInfo(const VEINTEROP_SESSION_INFO& veinteropSessionInfo)
{
    DeveloperTypes::sessionInfo sessionInfo;
    sessionInfo.sessionKeyPtr = veinteropSessionInfo.sessionKeyPtr;
    sessionInfo.sessionNonce = veinteropSessionInfo.sessionNonce;
    return sessionInfo;
}

// Helper function to clean up session information by calling CloseUserBoundKeySession
void CleanupSessionInfo(const DeveloperTypes::sessionInfo& sessionInfo)
{
    if (sessionInfo.sessionKeyPtr != 0)
    {
        // Convert sessionInfo to VEINTEROP_SESSION_INFO for the API call
        VEINTEROP_SESSION_INFO veinteropSessionInfo = ConvertToVeinteropSessionInfo(sessionInfo);
        CloseUserBoundKeySession(&veinteropSessionInfo);
    }
}

// RAII wrapper for USER_BOUND_KEY_AUTH_CONTEXT_HANDLE to prevent resource leaks
class unique_auth_context_handle
{
    public:
    unique_auth_context_handle() noexcept : m_handle(nullptr) {}

    explicit unique_auth_context_handle(USER_BOUND_KEY_AUTH_CONTEXT_HANDLE handle) noexcept : m_handle(handle) {}

    ~unique_auth_context_handle() noexcept
    {
        reset();
    }

    // Non-copyable
    unique_auth_context_handle(const unique_auth_context_handle&) = delete;
    unique_auth_context_handle& operator=(const unique_auth_context_handle&) = delete;

    // Movable
    unique_auth_context_handle(unique_auth_context_handle&& other) noexcept : m_handle(other.m_handle)
    {
        other.m_handle = nullptr;
    }

    unique_auth_context_handle& operator=(unique_auth_context_handle&& other) noexcept
    {
        if (this != &other)
        {
            reset();
            m_handle = other.m_handle;
            other.m_handle = nullptr;
        }
        return *this;
    }

    void reset(USER_BOUND_KEY_AUTH_CONTEXT_HANDLE new_handle = nullptr) noexcept
    {
        if (m_handle)
        {
            CloseUserBoundKeyAuthContextHandle(m_handle);
        }
        m_handle = new_handle;
    }

    USER_BOUND_KEY_AUTH_CONTEXT_HANDLE* put() noexcept
    {
        reset();
        return &m_handle;
    }

    USER_BOUND_KEY_AUTH_CONTEXT_HANDLE get() const noexcept
    {
        return m_handle;
    }

    explicit operator bool() const noexcept
    {
        return m_handle != nullptr;
    }

    private:
    USER_BOUND_KEY_AUTH_CONTEXT_HANDLE m_handle;
};

std::vector<uint8_t> GetEphemeralPublicKeyBytesFromBoundKeyBytes(wil::secure_vector<uint8_t> boundKeyBytes)
{
    // The bound key structure is created in CreateBoundKeyStructure() in vengcdll.cpp:
    // [enclave public key blob size (4 bytes)]
    // [enclave public key blob]  
    // [nonce (12 bytes)]
    // [encrypted user key size (4 bytes)]
    // [encrypted user key data]
    // [authentication tag (16 bytes)]

    // We need to extract the enclave public key blob (the "ephemeral public key")

    veil::vtl1::vtl0_functions::debug_print((L"DEBUG: GetEphemeralPublicKeyBytesFromBoundKeyBytes - Starting with boundKeyBytes.size(): " + std::to_wstring(boundKeyBytes.size())).c_str());

    if (boundKeyBytes.size() < sizeof(uint32_t))
    {
        veil::vtl1::vtl0_functions::debug_print(L"ERROR: GetEphemeralPublicKeyBytesFromBoundKeyBytes - Bound key bytes too small - missing size field");
        throw std::invalid_argument("Bound key bytes too small - missing size field");
    }

    const uint8_t* pCurrentPos = boundKeyBytes.data();

    // Read the enclave public key blob size (first 4 bytes)
    uint32_t enclavePublicKeyBlobSize = *reinterpret_cast<const uint32_t*>(pCurrentPos);
    pCurrentPos += sizeof(uint32_t);

    veil::vtl1::vtl0_functions::debug_print((L"DEBUG: GetEphemeralPublicKeyBytesFromBoundKeyBytes - enclavePublicKeyBlobSize: " + std::to_wstring(enclavePublicKeyBlobSize)).c_str());

    // Validate that we have enough data for the full public key blob
    size_t remainingBytes = boundKeyBytes.size() - sizeof(uint32_t);
    veil::vtl1::vtl0_functions::debug_print((L"DEBUG: GetEphemeralPublicKeyBytesFromBoundKeyBytes - remainingBytes: " + std::to_wstring(remainingBytes)).c_str());

    if (remainingBytes < enclavePublicKeyBlobSize)
    {
        veil::vtl1::vtl0_functions::debug_print((L"ERROR: GetEphemeralPublicKeyBytesFromBoundKeyBytes - Insufficient data for public key blob. Need: " + std::to_wstring(enclavePublicKeyBlobSize) + L", Have: " + std::to_wstring(remainingBytes)).c_str());
        throw std::runtime_error("Bound key bytes corrupted - insufficient data for public key blob");
    }

    // Additional validation: check for unreasonably large public key size
    if (enclavePublicKeyBlobSize > remainingBytes || enclavePublicKeyBlobSize == 0)
    {
        veil::vtl1::vtl0_functions::debug_print((L"ERROR: GetEphemeralPublicKeyBytesFromBoundKeyBytes - Invalid public key blob size: " + std::to_wstring(enclavePublicKeyBlobSize) + L" (remainingBytes: " + std::to_wstring(remainingBytes) + L")").c_str());

        // Add hex dump of first 16 bytes for debugging
        std::wstring hexDump = L"First 16 bytes of boundKeyBytes: ";
        size_t maxBytes = boundKeyBytes.size() < 16 ? boundKeyBytes.size() : 16;
        for (size_t i = 0; i < maxBytes; ++i)
        {
            wchar_t hexByte[4];
            swprintf_s(hexByte, L"%02X ", boundKeyBytes[i]);
            hexDump += hexByte;
        }
        veil::vtl1::vtl0_functions::debug_print(hexDump.c_str());

        throw std::runtime_error("Bound key bytes corrupted - invalid public key blob size");
    }

    // Extract the enclave public key blob
    std::vector<uint8_t> ephemeralPublicKey(pCurrentPos, pCurrentPos + enclavePublicKeyBlobSize);

    veil::vtl1::vtl0_functions::debug_print((L"DEBUG: GetEphemeralPublicKeyBytesFromBoundKeyBytes - Successfully extracted ephemeral public key, size: " + std::to_wstring(ephemeralPublicKey.size())).c_str());

    return ephemeralPublicKey;
}

wil::secure_vector<uint8_t> enclave_create_user_bound_key(
    const std::wstring& keyName,
    KEY_CREDENTIAL_CACHE_CONFIG& cacheConfig,
    const std::wstring& message,
    uintptr_t windowId,
    ENCLAVE_SEALING_IDENTITY_POLICY sealingPolicy)
{
    veil::vtl1::vtl0_functions::debug_print(L"DEBUG: enclave_create_user_bound_key - Function entered");

    DeveloperTypes::sessionInfo sessionInfo{}; // Initialize session info for cleanup

    try
    {
        // Convert cacheConfig to the type expected by the callback
        auto devCacheConfig = ConvertToDeveloperType(cacheConfig);

        veil::vtl1::vtl0_functions::debug_print(L"DEBUG: enclave_create_user_bound_key - ConvertToDeveloperType completed");

        // SESSION
        void* enclave = veil::vtl1::enclave_information().BaseAddress;
        auto authContextBlobAndSessionInfo = veil_abi::VTL0_Callbacks::userboundkey_establish_session_for_create_callback(
            reinterpret_cast<uint64_t>(enclave),
            keyName,
            reinterpret_cast<uintptr_t>(BCRYPT_ECDH_P384_ALG_HANDLE),
            message,
            windowId,
            devCacheConfig);

        veil::vtl1::vtl0_functions::debug_print(L"DEBUG: enclave_create_user_bound_key - Received authContextBlobAndSessionKeyPtr");

        auto& authContextBlob = authContextBlobAndSessionInfo.authContextBlob;
        // Extract session info from the response - the create callback returns sessionKeyPtr directly
        sessionInfo = authContextBlobAndSessionInfo.session;
        veil::vtl1::vtl0_functions::debug_print(L"DEBUG: enclave_create_user_bound_key - Received authContextBlob");

        // AUTH CONTEXT
        unique_auth_context_handle authContext;
        
        // Convert sessionInfo to VEINTEROP_SESSION_INFO for the API call
        VEINTEROP_SESSION_INFO veinteropSessionInfo = ConvertToVeinteropSessionInfo(sessionInfo);
        
        THROW_IF_FAILED(GetUserBoundKeyAuthContext(
            &veinteropSessionInfo,
            authContextBlob.data(),
            static_cast<UINT32>(authContextBlob.size()),
            authContext.put()
        )); // OS CALL
        
        veil::vtl1::vtl0_functions::debug_print(L"DEBUG: enclave_create_user_bound_key - GetUserBoundKeyAuthContext completed");

        // Validate
        USER_BOUND_KEY_AUTH_CONTEXT_PROPERTY propCacheConfig;
        propCacheConfig.name = UserBoundKeyAuthContextPropertyCacheConfig;
        propCacheConfig.size = sizeof(cacheConfig);
        propCacheConfig.value = &cacheConfig;

        THROW_IF_FAILED(ValidateUserBoundKeyAuthContext(authContext.get(), 1, &propCacheConfig)); // OS CALL
        veil::vtl1::vtl0_functions::debug_print(L"DEBUG: enclave_create_user_bound_key - ValidateUserBoundKeyAuthContext completed");

        // USERKEY
        auto userkeyBytes = veil::vtl1::crypto::generate_symmetric_key_bytes();
        veil::vtl1::vtl0_functions::debug_print(L"DEBUG: enclave_create_user_bound_key - Generated user key bytes");

        // ENCRYPT USERKEY - CORRECTED VERSION
        void* pBoundKey = nullptr;
        UINT32 cbBoundKeyBytes = 0;
        veil::vtl1::vtl0_functions::debug_print(L"DEBUG: enclave_create_user_bound_key - About to call ProtectUserBoundKey");
        THROW_IF_FAILED(ProtectUserBoundKey(
            authContext.get(),
            userkeyBytes.data(),
            static_cast<UINT32>(userkeyBytes.size()),
            &pBoundKey,        // ? CORRECT: address of pointer for dynamic allocation
            &cbBoundKeyBytes   // ? Will be set to actual size by ProtectUserBoundKey
        )); // OS CALL
        veil::vtl1::vtl0_functions::debug_print((L"DEBUG: enclave_create_user_bound_key - ProtectUserBoundKey returned boundKey size: " + std::to_wstring(cbBoundKeyBytes)).c_str());

        // Convert dynamically allocated buffer to vector for sealing
        std::vector<uint8_t> boundKeyBytes(
            static_cast<uint8_t*>(pBoundKey),
            static_cast<uint8_t*>(pBoundKey) + cbBoundKeyBytes
        );

        // Free the dynamically allocated memory
        HeapFree(GetProcessHeap(), 0, pBoundKey);

        veil::vtl1::vtl0_functions::debug_print((L"DEBUG: enclave_create_user_bound_key - Created boundKeyBytes vector with size: " + std::to_wstring(boundKeyBytes.size())).c_str());

        // Clean up session info before sealing
        CleanupSessionInfo(sessionInfo);

        // SEAL
        auto sealedKeyMaterial = veil::vtl1::crypto::seal_data(boundKeyBytes, sealingPolicy, ENCLAVE_RUNTIME_POLICY_ALLOW_FULL_DEBUG);
        veil::vtl1::vtl0_functions::debug_print(L"DEBUG: enclave_create_user_bound_key - Function completed successfully");
        return sealedKeyMaterial;
    }
    catch (const std::exception& e)
    {
        // Clean up session info on exception
        CleanupSessionInfo(sessionInfo);

        // Convert exception message to wide string for debug printing
        std::string error_msg = e.what();
        std::wstring werror_msg(error_msg.begin(), error_msg.end());
        veil::vtl1::vtl0_functions::debug_print((L"ERROR: enclave_create_user_bound_key - Exception caught: " + werror_msg).c_str());
        throw; // Re-throw the exception
    }
    catch (...)
    {
        // Clean up session info on exception
        CleanupSessionInfo(sessionInfo);

        veil::vtl1::vtl0_functions::debug_print(L"ERROR: enclave_create_user_bound_key - Unknown exception caught");
        throw; // Re-throw the exception
    }
}

std::vector<uint8_t> enclave_load_user_bound_key(
    const std::wstring& keyName,
    KEY_CREDENTIAL_CACHE_CONFIG& cacheConfig,
    const std::wstring& message,
    uintptr_t windowId,
    std::vector<uint8_t>& sealedBoundKeyBytes)
{
    veil::vtl1::vtl0_functions::debug_print(L"DEBUG: enclave_load_user_bound_key - Function entered");

    DeveloperTypes::sessionInfo sessionInfo{}; // Initialize session info for cleanup

    try
    {
        // UNSEAL
        veil::vtl1::vtl0_functions::debug_print(L"DEBUG: enclave_load_user_bound_key - About to call unseal_data");
        veil::vtl1::vtl0_functions::debug_print((L"DEBUG: enclave_load_user_bound_key - sealedBoundKeyBytes size: " + std::to_wstring(sealedBoundKeyBytes.size())).c_str());

        auto boundKeyBytesMaterial = veil::vtl1::crypto::unseal_data(sealedBoundKeyBytes);

        veil::vtl1::vtl0_functions::debug_print(L"DEBUG: enclave_load_user_bound_key - unseal_data completed successfully");

        auto& boundKeyBytes = boundKeyBytesMaterial.first;
        veil::vtl1::vtl0_functions::debug_print((L"DEBUG: enclave_load_user_bound_key - boundKeyBytes size: " + std::to_wstring(boundKeyBytes.size())).c_str());

        std::vector<uint8_t> ephemeralPublicKeyBytes = GetEphemeralPublicKeyBytesFromBoundKeyBytes(boundKeyBytes);
        veil::vtl1::vtl0_functions::debug_print((L"DEBUG: enclave_load_user_bound_key - ephemeralPublicKeyBytes size: " + std::to_wstring(ephemeralPublicKeyBytes.size())).c_str());

        // SESSION - First call to get credential and sessionInfo
        veil::vtl1::vtl0_functions::debug_print(L"DEBUG: enclave_load_user_bound_key - About to call establish_session_for_load_callback");

        void* enclave = veil::vtl1::enclave_information().BaseAddress;
        auto credentialAndFormattedKeyNameAndSessionInfoResult = veil::vtl1::implementation::userboundkey::callouts::userboundkey_establish_session_for_load_callback(
            enclave,
            keyName,
            ephemeralPublicKeyBytes,
            message,
            windowId);

        veil::vtl1::vtl0_functions::debug_print(L"DEBUG: enclave_load_user_bound_key - establish_session_for_load_callback completed");

        // Extract credential vector and session info from first call
        auto& credentialVector = credentialAndFormattedKeyNameAndSessionInfoResult.credential;
        sessionInfo = credentialAndFormattedKeyNameAndSessionInfoResult.session;
        auto& formattedKeyName = credentialAndFormattedKeyNameAndSessionInfoResult.formattedKeyName;

        veil::vtl1::vtl0_functions::debug_print((L"DEBUG: enclave_load_user_bound_key - credentialVector size: " + std::to_wstring(credentialVector.size())).c_str());
        veil::vtl1::vtl0_functions::debug_print((L"DEBUG: enclave_load_user_bound_key - sessionKeyPtr: 0x" + std::to_wstring(sessionInfo.sessionKeyPtr)).c_str());

        // Call to vengc to create the encrypted NGC request for DeriveSharedSecret
        void* encryptedNgcRequest = nullptr;
        UINT32 encryptedNgcRequestSize = 0;

        const void* keyNamePtr = formattedKeyName.c_str();
        UINT32 keyNameSizeBytes = static_cast<UINT32>(formattedKeyName.length() * sizeof(wchar_t)); // Exclude null terminator

        // DEBUG: Print formattedKeyName and keyNameSizeBytes
        veil::vtl1::vtl0_functions::debug_print((L"DEBUG: enclave_load_user_bound_key - formattedKeyName: " + formattedKeyName).c_str());
        veil::vtl1::vtl0_functions::debug_print((L"DEBUG: enclave_load_user_bound_key - keyNameSizeBytes (without null terminator): " + std::to_wstring(keyNameSizeBytes)).c_str());

        // Convert sessionInfo to VEINTEROP_SESSION_INFO for the API call
        VEINTEROP_SESSION_INFO veinteropSessionInfo = ConvertToVeinteropSessionInfo(sessionInfo);

        // Use the function that accepts VEINTEROP_SESSION_INFO and handles nonce manipulation internally
        THROW_IF_FAILED(CreateEncryptedRequestForDeriveSharedSecret(
            &veinteropSessionInfo,  // Pass converted sessionInfo by reference - nonce manipulation is handled internally
            keyNamePtr,
            keyNameSizeBytes,
            ephemeralPublicKeyBytes.data(),
            static_cast<UINT32>(ephemeralPublicKeyBytes.size()),
            &encryptedNgcRequest,
            &encryptedNgcRequestSize)); // OS CALL

        // Convert back to update the original sessionInfo
        sessionInfo = ConvertFromVeinteropSessionInfo(veinteropSessionInfo);

        // Convert the result to vector for the callback
        std::vector<uint8_t> encryptedNgcRequestForDeriveSharedSecret;
        if (encryptedNgcRequest != nullptr && encryptedNgcRequestSize > 0)
        {
            encryptedNgcRequestForDeriveSharedSecret.assign(
                static_cast<uint8_t*>(encryptedNgcRequest),
                static_cast<uint8_t*>(encryptedNgcRequest) + encryptedNgcRequestSize);

            // Free the allocated memory
            HeapFree(GetProcessHeap(), 0, encryptedNgcRequest);
        }

        // Second call to extract secret and authorization context from credential
        veil::vtl1::vtl0_functions::debug_print(L"DEBUG: enclave_load_user_bound_key - About to call userboundkey_get_secret_and_authorizationcontext_from_credential_callback");

        auto secretAndAuthorizationContext = veil::vtl1::implementation::userboundkey::callouts::userboundkey_get_secret_and_authorizationcontext_from_credential_callback(
            credentialVector,
            encryptedNgcRequestForDeriveSharedSecret,
            message,
            windowId);

        veil::vtl1::vtl0_functions::debug_print(L"DEBUG: enclave_load_user_bound_key - userboundkey_get_secret_and_authorizationcontext_from_credential_callback completed");

        auto& secret = secretAndAuthorizationContext.secret;
        auto& authContextBlob = secretAndAuthorizationContext.authorizationContext;

        veil::vtl1::vtl0_functions::debug_print((L"DEBUG: enclave_load_user_bound_key - secret size: " + std::to_wstring(secret.size())).c_str());
        veil::vtl1::vtl0_functions::debug_print((L"DEBUG: enclave_load_user_bound_key - authContextBlob size: " + std::to_wstring(authContextBlob.size())).c_str());

        // AUTH CONTEXT
        veil::vtl1::vtl0_functions::debug_print(L"DEBUG: enclave_load_user_bound_key - About to call GetUserBoundKeyAuthContext");
        unique_auth_context_handle authContext;
        
        // Convert sessionInfo to VEINTEROP_SESSION_INFO for the API call
        VEINTEROP_SESSION_INFO veinteropSessionInfoForAuth = ConvertToVeinteropSessionInfo(sessionInfo);
        
        THROW_IF_FAILED(GetUserBoundKeyAuthContext(
            &veinteropSessionInfoForAuth,
            authContextBlob.data(),
            static_cast<UINT32>(authContextBlob.size()),
            authContext.put())); // OS CALL
        veil::vtl1::vtl0_functions::debug_print(L"DEBUG: enclave_load_user_bound_key - GetUserBoundKeyAuthContext completed");

        // Validate
        veil::vtl1::vtl0_functions::debug_print(L"DEBUG: enclave_load_user_bound_key - About to validate auth context");
        USER_BOUND_KEY_AUTH_CONTEXT_PROPERTY propCacheConfig;
        propCacheConfig.name = UserBoundKeyAuthContextPropertyCacheConfig;
        propCacheConfig.size = sizeof(cacheConfig);
        propCacheConfig.value = &cacheConfig;
        THROW_IF_FAILED(ValidateUserBoundKeyAuthContext(authContext.get(), 1, &propCacheConfig)); // OS CALL
        veil::vtl1::vtl0_functions::debug_print(L"DEBUG: enclave_load_user_bound_key - Auth context validation completed");

        // DECRYPT USERKEY
        veil::vtl1::vtl0_functions::debug_print(L"DEBUG: enclave_load_user_bound_key - About to call UnprotectUserBoundKey");
        UINT32 cbUserkeyBytes = 0;
        void* pUserkeyBytes = nullptr;

        // Convert sessionInfo to VEINTEROP_SESSION_INFO for the API call
        VEINTEROP_SESSION_INFO unprotectSessionInfo = ConvertToVeinteropSessionInfo(sessionInfo);

        THROW_IF_FAILED(UnprotectUserBoundKey(
            &unprotectSessionInfo,
            authContext.get(),
            secret.data(),
            static_cast<UINT32>(secret.size()),
            boundKeyBytes.data(),
            static_cast<UINT32>(boundKeyBytes.size()),
            &pUserkeyBytes,
            &cbUserkeyBytes)); // OS CALL
        veil::vtl1::vtl0_functions::debug_print(L"DEBUG: enclave_load_user_bound_key - UnprotectUserBoundKey completed");

        std::vector<uint8_t> userkeyBytes(static_cast<uint8_t*>(pUserkeyBytes), static_cast<uint8_t*>(pUserkeyBytes) + cbUserkeyBytes);
        HeapFree(GetProcessHeap(), 0, pUserkeyBytes);

        // Clean up session key before returning
        CleanupSessionInfo(sessionInfo);

        veil::vtl1::vtl0_functions::debug_print(L"DEBUG: enclave_load_user_bound_key - Function completed successfully");
        return userkeyBytes;
    }
    catch (const std::exception& e)
    {
        // Clean up session key on exception
        CleanupSessionInfo(sessionInfo);

        // Convert exception message to wide string for debug printing
        std::string error_msg = e.what();
        std::wstring werror_msg(error_msg.begin(), error_msg.end());
        veil::vtl1::vtl0_functions::debug_print((L"ERROR: enclave_load_user_bound_key - Exception caught: " + werror_msg).c_str());
        throw; // Re-throw the exception
    }
    catch (...)
    {
        // Clean up session key on exception
        CleanupSessionInfo(sessionInfo);

        veil::vtl1::vtl0_functions::debug_print(L"ERROR: enclave_load_user_bound_key - Unknown exception caught");
        throw; // Re-throw the exception
    }
}
} // namespace veil::vtl1::userboundkey
