#pragma once

#include <functional>
#include <future>
#include <string>
#include <tuple>
#include <vector>
#include <memory>
#include <iostream>

// Include Windows headers first to define basic types
#include <windows.h>
#include <ntenclv.h>
#include <enclaveium.h>
#include <roapi.h>
#include <winstring.h>
#include <unknwn.h>  // For IUnknown interface

#include <winrt/base.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Security.Credentials.h>
#include <winrt/Windows.Security.Cryptography.h>
#include <winrt/Windows.Security.Cryptography.Certificates.h>
#include <winrt/Windows.Storage.Streams.h>

#include <VbsEnclave\HostApp\Implementation\Untrusted.h>
#include <VbsEnclave\HostApp\Stubs\Trusted.h>
#include <veinterop_kcm.h>
#include <wil/token_helpers.h>
#include <wil/resource.h>
#include <sddl.h>

using namespace winrt::Windows::Security::Credentials;

namespace veil::vtl0::userboundkey::implementation
{
// RAII wrapper that stores both the session handle and enclave pointer
class unique_sessionhandle
{
    public:
    unique_sessionhandle() = default;

    // Move constructor
    unique_sessionhandle(unique_sessionhandle&& other) noexcept
        : m_handle(std::exchange(other.m_handle, nullptr))
        , m_enclavePtr(std::exchange(other.m_enclavePtr, nullptr))
    {
    }

    // Move assignment
    unique_sessionhandle& operator=(unique_sessionhandle&& other) noexcept
    {
        if (this != &other)
        {
            reset();
            m_handle = std::exchange(other.m_handle, nullptr);
            m_enclavePtr = std::exchange(other.m_enclavePtr, nullptr);
        }
        return *this;
    }

    // Delete copy operations
    unique_sessionhandle(const unique_sessionhandle&) = delete;
    unique_sessionhandle& operator=(const unique_sessionhandle&) = delete;

    ~unique_sessionhandle()
    {
        reset();
    }

    void reset()
    {
        if (m_handle != nullptr && m_enclavePtr != nullptr)
        {
            try
            {
                std::wcout << L"DEBUG: VTL0 unique_sessionhandle cleanup - calling into VTL1" << std::endl;
                auto sessionInfo = reinterpret_cast<uintptr_t>(m_handle);
                auto enclaveInterface = veil_abi::Trusted::Stubs::export_interface(m_enclavePtr);
                enclaveInterface.userboundkey_close_session(sessionInfo);
                std::wcout << L"DEBUG: VTL0 session cleanup completed successfully" << std::endl;
            }
            catch (const std::exception& e)
            {
                std::wcout << L"ERROR: Exception during VTL0 session cleanup: " << e.what() << std::endl;
            }
            catch (...)
            {
                std::wcout << L"ERROR: Unknown exception during VTL0 session cleanup" << std::endl;
            }
        }
        m_handle = nullptr;
        m_enclavePtr = nullptr;
    }

    USER_BOUND_KEY_SESSION_HANDLE get() const noexcept { return m_handle; }

    USER_BOUND_KEY_SESSION_HANDLE release() noexcept
    {
        auto result = m_handle;
        m_handle = nullptr;
        m_enclavePtr = nullptr;
        return result;
    }

    void set(USER_BOUND_KEY_SESSION_HANDLE handle, void* enclavePtr)
    {
        reset();
        m_handle = handle;
        m_enclavePtr = enclavePtr;
    }

    private:
    USER_BOUND_KEY_SESSION_HANDLE m_handle = nullptr;
    void* m_enclavePtr = nullptr;
};
}

// Helper function to convert WinRT IBuffer to std::vector<uint8_t>
std::vector<uint8_t> ConvertBufferToVector(winrt::Windows::Storage::Streams::IBuffer const& buffer)
{
    winrt::com_array<uint8_t> byteArray;
    winrt::Windows::Security::Cryptography::CryptographicBuffer::CopyToByteArray(buffer, byteArray);
    return std::vector<uint8_t>(byteArray.begin(), byteArray.end());
}

// Helper function for common challenge callback logic
std::function<winrt::Windows::Storage::Streams::IBuffer(const winrt::Windows::Storage::Streams::IBuffer&)> 
CreateChallengeCallback(std::shared_ptr<veil::vtl0::userboundkey::implementation::unique_sessionhandle> sessionInfo, void* enclaveptr, const std::wstring& callbackType)
{
    return [sessionInfo, enclaveptr, callbackType](const auto& challenge) mutable -> winrt::Windows::Storage::Streams::IBuffer
    {
        std::wcout << L"DEBUG: " << callbackType << L" callback challenge invoked! Challenge size: " << challenge.Length() << std::endl;
  
        try {
            auto enclaveInterface = veil_abi::Trusted::Stubs::export_interface(enclaveptr);

            std::wcout << L"DEBUG: Converting challenge buffer..." << std::endl;
            auto challengeVector = ConvertBufferToVector(challenge);
            std::wcout << L"DEBUG: Challenge vector size: " << challengeVector.size() << std::endl;

            std::wcout << L"DEBUG: About to call userboundkey_get_attestation_report (" << callbackType << L" callback)..." << std::endl;
            auto attestationReportAndSessionInfo = enclaveInterface.userboundkey_get_attestation_report(challengeVector);
            std::wcout << L"DEBUG: userboundkey_get_attestation_report returned successfully (" << callbackType << L" callback)!" << std::endl;

            // Store the session handle in the RAII wrapper with enclave pointer
            sessionInfo->set(
                reinterpret_cast<USER_BOUND_KEY_SESSION_HANDLE>(attestationReportAndSessionInfo.sessionInfo),
                enclaveptr
            );
            if (callbackType == L"Challenge") {
                std::wcout << L"DEBUG: Session stored: " << reinterpret_cast<uintptr_t>(sessionInfo->get()) << std::endl;
            }
      
            // Convert std::vector<uint8_t> back to IBuffer for return
            std::wcout << L"DEBUG: Converting attestation report back to IBuffer..." << std::endl;
            auto result = winrt::Windows::Security::Cryptography::CryptographicBuffer::CreateFromByteArray(attestationReportAndSessionInfo.attestationReport);
            std::wcout << L"DEBUG: " << callbackType << L" callback completed successfully!" << std::endl;
            return result;
        }
        catch (const std::exception& e) {
            std::wcout << L"DEBUG: Exception in " << callbackType << L" callback: " << e.what() << std::endl;
            throw;
        }
        catch (...) {
            std::wcout << L"DEBUG: Unknown exception in " << callbackType << L" callback!" << std::endl;
            throw;
        }
    };
}

std::wstring FormatUserHelloKeyName(PCWSTR name)
{
    static constexpr wchar_t c_formatString[] = L"{}//{}//{}";
    
    wil::unique_handle processToken;
    THROW_LAST_ERROR_IF(!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &processToken));

    auto tokenUser = wil::get_token_information<TOKEN_USER>(processToken.get());

    // Extract the SID from the TOKEN_USER structure
    PSID userSid = tokenUser->User.Sid;

    // Convert SID to string
    wil::unique_hlocal_ptr<WCHAR[]> userSidString;
    THROW_LAST_ERROR_IF(!ConvertSidToStringSidW(userSid, wil::out_param_ptr<LPWSTR*>(userSidString)));

    // Create the formatted key name
    std::wstring result = std::format(c_formatString, userSidString.get(), userSidString.get(), name);

    return result;
}

winrt::hstring GetAlgorithm(uintptr_t ecdhAlgorithm)
{
    using namespace winrt::Windows::Security::Cryptography::Certificates;
    if (reinterpret_cast<BCRYPT_ALG_HANDLE>(ecdhAlgorithm) == BCRYPT_ECDH_P384_ALG_HANDLE)
    {
        return KeyAlgorithmNames::Ecdh384();
    }
    else if (reinterpret_cast<BCRYPT_ALG_HANDLE>(ecdhAlgorithm) == BCRYPT_ECDH_P256_ALG_HANDLE)
    {
        return KeyAlgorithmNames::Ecdh256();
    }
    THROW_HR(E_INVALIDARG);
}

// Helper function to convert veil_abi::Types::keyCredentialCacheConfig to KeyCredentialCacheConfiguration
KeyCredentialCacheConfiguration ConvertCacheConfig(const veil_abi::Types::keyCredentialCacheConfig& cacheConfig)
{
    // Map cacheOption to KeyCredentialCacheOption
    KeyCredentialCacheOption cacheOption;
    switch (cacheConfig.cacheOption)
    {
        case 0:
            cacheOption = KeyCredentialCacheOption::NoCache;
            break;
        case 1:
            cacheOption = KeyCredentialCacheOption::CacheWhenUnlocked;
            break;
        default:
            cacheOption = KeyCredentialCacheOption::NoCache; // Default fallback
            break;
    }

    // Convert timeout from seconds to TimeSpan (100-nanosecond units)
    winrt::Windows::Foundation::TimeSpan timeout{ static_cast<int64_t>(cacheConfig.cacheTimeoutInSeconds) * 10000000LL };

    // Use WinRT's get_activation_factory for a more modern approach
    auto factory = winrt::get_activation_factory<winrt::Windows::Security::Credentials::KeyCredentialCacheConfiguration, 
                                                 winrt::Windows::Security::Credentials::IKeyCredentialCacheConfigurationFactory>();

    return factory.CreateInstance(cacheOption, timeout, cacheConfig.cacheUsageCount);
}

veil_abi::Types::credentialAndSessionInfo veil_abi::Untrusted::Implementation::userboundkey_establish_session_for_create(
    uintptr_t enclave,
    const std::wstring& key_name,
    uintptr_t ecdh_protocol,
    const std::wstring& message,
    uintptr_t window_id,
    const veil_abi::Types::keyCredentialCacheConfig& cache_config,
    uint32_t key_credential_creation_option)
{
    std::wcout << L"Inside userboundkey_establish_session_for_create_callback"<< std::endl;
    auto algorithm = GetAlgorithm(ecdh_protocol);

    // Convert the cacheConfig parameter to KeyCredentialCacheConfiguration
    auto cacheConfiguration = ConvertCacheConfig(cache_config);

    auto sessionInfo = std::make_shared<veil::vtl0::userboundkey::implementation::unique_sessionhandle>();
    auto enclaveptr = (void*)enclave;   

    try
    {
        auto op = KeyCredentialManager::DeleteAsync(key_name);
        std::wcout << "Deletion worked" << std::endl;
        op.get();
    }
    catch (...)
    {
        std::wcout << "Deletion failed" << std::endl;
    }
  
    std::wcout << L"Calling RequestCreateAsync" << std::endl;
    auto credentialResult = KeyCredentialManager::RequestCreateAsync(
        key_name,
        static_cast<KeyCredentialCreationOption>(key_credential_creation_option),
        algorithm,
        message,
        cacheConfiguration,
        static_cast<winrt::Windows::UI::WindowId>(window_id),
        ChallengeResponseKind::VirtualizationBasedSecurityEnclave,
        CreateChallengeCallback(sessionInfo, enclaveptr, L"Create")
    ).get();

    std::wcout << L"RequestCreateAsync returned" << std::endl;

    // Check if the operation was successful
    auto status = credentialResult.Status();
    if (status != KeyCredentialStatus::Success)
    {        
        THROW_HR(static_cast<HRESULT>(status));
    }

    std::wcout << L"DEBUG: Transferring credential and session ownership to VTL1" << std::endl;

    credentialAndSessionInfo result;
    void* tempCredential = nullptr;
    winrt::copy_to_abi(credentialResult.Credential(), tempCredential);

    result.credential = reinterpret_cast<uintptr_t>(tempCredential);
    result.sessionInfo = reinterpret_cast<uintptr_t>(sessionInfo->release()); // Transfer ownership to VTL1

    return result;
}

veil_abi::Types::credentialAndSessionInfo veil_abi::Untrusted::Implementation::userboundkey_establish_session_for_load(
    uintptr_t enclave,
    const std::wstring& key_name,
    const std::wstring& message,
    uintptr_t window_id)
{
    auto sessionInfo = std::make_shared<veil::vtl0::userboundkey::implementation::unique_sessionhandle>();
    auto enclaveptr = (void*)enclave;

    auto credentialResult = KeyCredentialManager::OpenAsync(
        key_name.c_str(),
        ChallengeResponseKind::VirtualizationBasedSecurityEnclave,
        CreateChallengeCallback(sessionInfo, enclaveptr, L"Load")
    ).get();

    // Check if the operation was successful
    auto status = credentialResult.Status();
    if (status != KeyCredentialStatus::Success)
    {
        THROW_HR(static_cast<HRESULT>(status));
    }
    
    std::wcout << L"DEBUG: Transferring credential and session ownership to VTL1" << std::endl;

    credentialAndSessionInfo result;
    void* tempCredential = nullptr;
    winrt::copy_to_abi(credentialResult.Credential(), tempCredential);

    result.credential = reinterpret_cast<uintptr_t>(tempCredential);
    result.sessionInfo = reinterpret_cast<uintptr_t>(sessionInfo->release()); // Transfer ownership to VTL1  
    
    return result;
}

// VTL0 function to extract authorization context from credential
std::vector<uint8_t> veil_abi::Untrusted::Implementation::userboundkey_get_authorization_context_from_credential(
    uintptr_t credential_ptr,
    const std::vector<uint8_t>& encrypted_kcm_request_for_get_authorization_context,
    const std::wstring& message,
    uintptr_t window_id)
{
    std::wcout << L"DEBUG: userboundkey_get_authorization_context_from_credential called with credential: 0x" 
        << std::hex << credential_ptr << std::dec << std::endl;

    try
    {
        // Directly attach to the existing COM object with one reference
        // This creates a non-owning wrapper that won't call Release
        void* abi = reinterpret_cast<void*>(credential_ptr);
        KeyCredential credential { nullptr };
        winrt::copy_from_abi(credential, abi);
   
        std::wcout << L"DEBUG: Created non-owning KeyCredential wrapper" << std::endl;

        // Extract authorization context
        auto authorizationContext = credential.RetrieveAuthorizationContext(
        winrt::Windows::Security::Cryptography::CryptographicBuffer::CreateFromByteArray(encrypted_kcm_request_for_get_authorization_context));

        auto result = ConvertBufferToVector(authorizationContext);

        std::wcout << L"DEBUG: userboundkey_get_authorization_context_from_credential completed successfully" << std::endl;
  
        return result;
    }
    catch (const std::exception& e)
    {
        std::wcout << L"DEBUG: Exception in userboundkey_get_authorization_context_from_credential: " << e.what() << std::endl;
        throw;
    }
    catch (...)
    {
        std::wcout << L"DEBUG: Unknown exception in userboundkey_get_authorization_context_from_credential" << std::endl;
        throw;
    }
}

// New VTL0 function to extract secret from credential
std::vector<uint8_t> veil_abi::Untrusted::Implementation::userboundkey_get_secret_from_credential(
    uintptr_t credential_ptr,
    const std::vector<uint8_t>& encrypted_kcm_request_for_derive_shared_secret,
    const std::wstring& message,
    uintptr_t window_id)
{
    std::wcout << L"DEBUG: userboundkey_get_secret_from_credential called with credential: 0x" 
        << std::hex << credential_ptr << std::dec << std::endl;

    try
    {
        // Directly attach to the existing COM object with one reference
        // This creates a non-owning wrapper that won't call Release
        void* abi = reinterpret_cast<void*>(credential_ptr);
        KeyCredential credential {nullptr};
        winrt::copy_from_abi(credential, abi);

        std::wcout << L"DEBUG: Created non-owning KeyCredential wrapper" << std::endl;

        // Derive shared secret. This prompts for the hello PIN.
        auto secret = credential.RequestDeriveSharedSecretAsync(
            (winrt::Windows::UI::WindowId)window_id,
            message,
            winrt::Windows::Security::Cryptography::CryptographicBuffer::CreateFromByteArray(encrypted_kcm_request_for_derive_shared_secret)).get();

        auto result = ConvertBufferToVector(secret.Result());
  
        std::wcout << L"DEBUG: userboundkey_get_secret_from_credential completed successfully" << std::endl;

        return result;
    }
    catch (const std::exception& e)
    {
        std::wcout << L"DEBUG: Exception in userboundkey_get_secret_from_credential: " << e.what() << std::endl;
        throw;
    }
    catch (...)
    {
        std::wcout << L"DEBUG: Unknown exception in userboundkey_get_secret_from_credential" << std::endl;
        throw;
    }
}

// Format a key name with SID information for use with Windows Hello
std::wstring veil_abi::Untrusted::Implementation::userboundkey_format_key_name(const std::wstring& key_name)
{
    return FormatUserHelloKeyName(key_name.c_str());
}

// VTL0 function to safely delete/release a credential using WinRT ownership patterns
void veil_abi::Untrusted::Implementation::userboundkey_delete_credential(uintptr_t credential_ptr)
{
    std::wcout << L"DEBUG: userboundkey_delete_credential called with credential: 0x" 
        << std::hex << credential_ptr << std::dec << std::endl;

    if (credential_ptr == 0)
    {
        std::wcout << L"DEBUG: userboundkey_delete_credential - credential_ptr is null, nothing to delete" << std::endl;
        return;
    }

    try
    {
        void* abi = reinterpret_cast<void*>(credential_ptr);
        KeyCredential credential{ abi, winrt::take_ownership_from_abi };
  
        std::wcout << L"DEBUG: userboundkey_delete_credential - Created owning KeyCredential wrapper via take_ownership_from_abi" << std::endl;

        auto released_abi = winrt::detach_abi(credential);
     
        std::wcout << L"DEBUG: userboundkey_delete_credential - Called detach_abi, released_abi: 0x" 
            << std::hex << reinterpret_cast<uintptr_t>(released_abi) << std::dec << std::endl;
        
        std::wcout << L"DEBUG: userboundkey_delete_credential - KeyCredential wrapper going out of scope, will call proper cleanup" << std::endl;
    }
    catch (const std::exception& e)
    {
        std::wcout << L"DEBUG: Exception in userboundkey_delete_credential: " << e.what() << std::endl;
    }
    catch (...)
    {
        std::wcout << L"DEBUG: Unknown exception in userboundkey_delete_credential" << std::endl;
    }
    
    std::wcout << L"DEBUG: userboundkey_delete_credential completed" << std::endl;
}
