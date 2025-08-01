#include "pch.h"
#include <VbsEnclave\Enclave\Implementations.h>
#include "crypto.vtl1.h"
#include "utils.vtl1.h"
#include "vengcdll.h" // OS APIs
#include "userboundkey.vtl1.h" // Function declarations

namespace veil_abi::VTL1_Declarations
{
attestationReportAndSessionKeyPtr userboundkey_get_attestation_report(_In_ const std::vector<std::uint8_t>& challenge)
{
    uint8_t* reportPtr = nullptr;
    void* tempReportPtr = nullptr; // Temporary variable of type void*
    size_t reportSize = 0;

    UINT_PTR sessionKeyPtr = 0;
    UINT32 sessionKeySize = 0;

    THROW_IF_FAILED(InitializeUserBoundKeySessionInfo(
        const_cast<uint8_t*>(challenge.data()),
        static_cast<UINT32>(challenge.size()),
        &tempReportPtr,
        reinterpret_cast<UINT32*>(&reportSize),
        &sessionKeyPtr,
        &sessionKeySize)); // OS CALL

    reportPtr = static_cast<uint8_t*>(tempReportPtr); // Cast back to uint8_t*
    std::vector<uint8_t> report(reportPtr, reportPtr + reportSize);
    CoTaskMemFree(reportPtr);

    return attestationReportAndSessionKeyPtr {std::move(report), static_cast<std::uintptr_t>(sessionKeyPtr)};
}
}

namespace veil::vtl1::userboundkey
{
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

std::vector<uint8_t> GetEphemeralPublicKeyBytesFromBoundKeyBytes(wil::secure_vector<uint8_t> /*boundKeyBytes*/)
{
    // TODO: implemententation
    return {};
}

wil::secure_vector<uint8_t> enclave_create_user_bound_key(
    const std::wstring& keyName,
    KEY_CREDENTIAL_CACHE_CONFIG& cacheConfig,
    const std::wstring& message,
    uintptr_t windowId,
    ENCLAVE_SEALING_IDENTITY_POLICY sealingPolicy)
{
    // SESSION
    auto authContextBlobAndSessionKeyPtr = veil_abi::VTL0_Callbacks::userboundkey_establish_session_for_create_callback(keyName, reinterpret_cast<uintptr_t>(BCRYPT_ECDH_P384_ALG_HANDLE), message, windowId);
    auto& authContextBlob = authContextBlobAndSessionKeyPtr.authContextBlob;

    // AUTH CONTEXT
    unique_auth_context_handle authContext;
    THROW_IF_FAILED(GetUserBoundKeyCreationAuthContext(
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

    THROW_IF_FAILED(ValidateUserBoundKeyAuthContext(keyName.c_str(), authContext.get(), 1, &propCacheConfig)); // OS CALL

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
    THROW_IF_FAILED(GetUserBoundKeyLoadingAuthContext(
        sessionKeyPtr,
        authContextBlob.data(),
        static_cast<UINT32>(authContextBlob.size()),
        authContext.put())); // OS CALL

    // Validate
    USER_BOUND_KEY_AUTH_CONTEXT_PROPERTY propCacheConfig;
    propCacheConfig.name = UserBoundKeyAuthContextPropertyCacheConfig;
    propCacheConfig.size = sizeof(cacheConfig);
    propCacheConfig.value = &cacheConfig;
    THROW_IF_FAILED(ValidateUserBoundKeyAuthContext(keyName.c_str(), authContext.get(), 1, &propCacheConfig)); // OS CALL

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
