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

    UINT_PTR sessionKeyPtr = 0;

    // DEBUG: Log before calling InitializeUserBoundKeySessionInfo
    veil::vtl1::vtl0_functions::debug_print(L"DEBUG: About to call InitializeUserBoundKeySessionInfo");

    THROW_IF_FAILED(InitializeUserBoundKeySessionInfo(
        const_cast<uint8_t*>(challenge.data()),
        static_cast<UINT32>(challenge.size()),
        &tempReportPtr,
        reinterpret_cast<UINT32*>(&reportSize),
        &sessionKeyPtr)); // OS CALL

    // DEBUG: Log after InitializeUserBoundKeySessionInfo completes
    veil::vtl1::vtl0_functions::debug_print(L"DEBUG: InitializeUserBoundKeySessionInfo completed successfully");

    reportPtr = static_cast<uint8_t*>(tempReportPtr); // Cast back to uint8_t*
    std::vector<uint8_t> report(reportPtr, reportPtr + reportSize);
    
    HeapFree(GetProcessHeap(), 0, reportPtr);

    // DEBUG: Log before returning
    veil::vtl1::vtl0_functions::debug_print(L"DEBUG: userboundkey_get_attestation_report returning successfully");

    return DeveloperTypes::attestationReportAndSessionKeyPtr {std::move(report), static_cast<std::uintptr_t>(sessionKeyPtr)};
}
}

namespace veil::vtl1::implementation::userboundkey::callouts
{
    DeveloperTypes::authContextBlobAndSessionKeyPtr userboundkey_establish_session_for_create_callback(
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

    DeveloperTypes::secretAndAuthorizationContextAndSessionKeyPtr userboundkey_establish_session_for_load_callback(
        _In_ const std::wstring& key_name, 
        _In_ const std::vector<std::uint8_t>& public_key, 
        _In_ const std::wstring& message, 
        _In_ const uintptr_t window_id)
    {
        return veil_abi::VTL0_Callbacks::userboundkey_establish_session_for_load_callback(
            key_name,
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

    if (boundKeyBytes.size() < sizeof(uint32_t))
    {
        // Not enough data for even the size field
        throw std::invalid_argument("Bound key bytes too small - missing size field");
    }

    const uint8_t* pCurrentPos = boundKeyBytes.data();
    
    // Read the enclave public key blob size (first 4 bytes)
    uint32_t enclavePublicKeyBlobSize = *reinterpret_cast<const uint32_t*>(pCurrentPos);
    pCurrentPos += sizeof(uint32_t);
    
    // Validate that we have enough data for the full public key blob
    size_t remainingBytes = boundKeyBytes.size() - sizeof(uint32_t);
    if (remainingBytes < enclavePublicKeyBlobSize)
    {
        // Not enough data for the public key blob
        throw std::runtime_error("Bound key bytes corrupted - insufficient data for public key blob");
    }
    
    // Additional validation: check for unreasonably large public key size
    if (enclavePublicKeyBlobSize > remainingBytes || enclavePublicKeyBlobSize == 0)
    {
        throw std::runtime_error("Bound key bytes corrupted - invalid public key blob size");
    }
    
    // Extract the enclave public key blob
    std::vector<uint8_t> ephemeralPublicKey(pCurrentPos, pCurrentPos + enclavePublicKeyBlobSize);
    
    return ephemeralPublicKey;
}

wil::secure_vector<uint8_t> enclave_create_user_bound_key(
    const std::wstring& keyName,
    KEY_CREDENTIAL_CACHE_CONFIG& cacheConfig,
    const std::wstring& message,
    uintptr_t windowId,
    ENCLAVE_SEALING_IDENTITY_POLICY sealingPolicy)
{
    veil::vtl1::vtl0_functions::debug_print(L"In enclave_create_user_bound_key");

    // Convert cacheConfig to the type expected by the callback
    auto devCacheConfig = ConvertToDeveloperType(cacheConfig);

    veil::vtl1::vtl0_functions::debug_print(L"ConvertToDeveloperType");

    // SESSION
    void* enclave = veil::vtl1::enclave_information().BaseAddress;
    auto authContextBlobAndSessionKeyPtr = veil_abi::VTL0_Callbacks::userboundkey_establish_session_for_create_callback(
        reinterpret_cast<uint64_t>(enclave),
        keyName,
        reinterpret_cast<uintptr_t>(BCRYPT_ECDH_P384_ALG_HANDLE),
        message,
        windowId,
        devCacheConfig);

    veil::vtl1::vtl0_functions::debug_print(L"Received authContextBlobAndSessionKeyPtr");

    auto& authContextBlob = authContextBlobAndSessionKeyPtr.authContextBlob;
    veil::vtl1::vtl0_functions::debug_print(L"Received authContextBlob");

    // AUTH CONTEXT
    unique_auth_context_handle authContext;
    THROW_IF_FAILED(GetUserBoundKeyAuthContext(
        authContextBlobAndSessionKeyPtr.sessionKeyPtr,
        authContextBlob.data(),
        static_cast<UINT32>(authContextBlob.size()),
        authContext.put()
    )); // OS CALL

    // Validate
    USER_BOUND_KEY_AUTH_CONTEXT_PROPERTY propCacheConfig;
    propCacheConfig.name = UserBoundKeyAuthContextPropertyCacheConfig;
    propCacheConfig.size = sizeof(cacheConfig);
    propCacheConfig.value = &cacheConfig;

    THROW_IF_FAILED(ValidateUserBoundKeyAuthContext(authContext.get(), 1, &propCacheConfig)); // OS CALL

    // USERKEY
    auto userkeyBytes = veil::vtl1::crypto::generate_symmetric_key_bytes();

    // ENCRYPT USERKEY
    std::vector<uint8_t> boundKeyBytes(256);
    UINT32 cbBoundKeyBytes = static_cast<UINT32>(boundKeyBytes.size());
    THROW_IF_FAILED(ProtectUserBoundKey(authContext.get(), userkeyBytes.data(), static_cast<UINT32>(userkeyBytes.size()), (void**)boundKeyBytes.data(), &cbBoundKeyBytes)); // OS CALL

    // SEAL
    auto sealedKeyMaterial = veil::vtl1::crypto::seal_data(boundKeyBytes, sealingPolicy, ENCLAVE_RUNTIME_POLICY_ALLOW_FULL_DEBUG);
    return sealedKeyMaterial;
}

std::vector<uint8_t> enclave_load_user_bound_key(
    const std::wstring& keyName,
    KEY_CREDENTIAL_CACHE_CONFIG& cacheConfig,
    const std::wstring& message,
    uintptr_t windowId,
    std::vector<uint8_t>& sealedBoundKeyBytes)
{
    // UNSEAL
    auto boundKeyBytesMaterial = veil::vtl1::crypto::unseal_data(sealedBoundKeyBytes);
    auto& boundKeyBytes = boundKeyBytesMaterial.first;
    std::vector<uint8_t> ephemeralPublicKeyBytes = GetEphemeralPublicKeyBytesFromBoundKeyBytes(boundKeyBytes);

    // SESSION
    auto secretAndAuthorizationContextAndSessionKeyPtr = veil_abi::VTL0_Callbacks::userboundkey_establish_session_for_load_callback(keyName, ephemeralPublicKeyBytes, message, windowId);

    auto& secret = secretAndAuthorizationContextAndSessionKeyPtr.secret;
    auto& authContextBlob = secretAndAuthorizationContextAndSessionKeyPtr.authorizationContext;
    auto sessionKeyPtr = secretAndAuthorizationContextAndSessionKeyPtr.sessionKeyPtr;

    // AUTH CONTEXT
    unique_auth_context_handle authContext;
    /*
    THROW_IF_FAILED(GetUserBoundKeyLoadingAuthContext(
        sessionKeyPtr,
        authContextBlob.data(),
        static_cast<UINT32>(authContextBlob.size()),
        authContext.put())); // OS CALL */
    THROW_IF_FAILED(GetUserBoundKeyAuthContext(
        sessionKeyPtr,
        authContextBlob.data(),
        static_cast<UINT32>(authContextBlob.size()),
        authContext.put())); // OS CALL

    // Validate
    USER_BOUND_KEY_AUTH_CONTEXT_PROPERTY propCacheConfig;
    propCacheConfig.name = UserBoundKeyAuthContextPropertyCacheConfig;
    propCacheConfig.size = sizeof(cacheConfig);
    propCacheConfig.value = &cacheConfig;
    THROW_IF_FAILED(ValidateUserBoundKeyAuthContext(authContext.get(), 1, &propCacheConfig)); // OS CALL

    // DECRYPT USERKEY
    UINT32 cbUserkeyBytes = 0;
    void* pUserkeyBytes = nullptr;
    THROW_IF_FAILED(UnprotectUserBoundKey(
        authContext.get(),
        secret.data(),
        static_cast<UINT32>(secret.size()),
        boundKeyBytes.data(),
        static_cast<UINT32>(boundKeyBytes.size()),
        &pUserkeyBytes,
        &cbUserkeyBytes)); // OS CALL

    std::vector<uint8_t> userkeyBytes(static_cast<uint8_t*>(pUserkeyBytes), static_cast<uint8_t*>(pUserkeyBytes) + cbUserkeyBytes);
    HeapFree(GetProcessHeap(), 0, pUserkeyBytes);

    return userkeyBytes;
}
}
