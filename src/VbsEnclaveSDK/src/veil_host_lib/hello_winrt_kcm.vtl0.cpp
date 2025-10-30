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
#include <sddl.h>

using namespace winrt::Windows::Security::Credentials;

// Helper function to convert WinRT IBuffer to std::vector<uint8_t>
std::vector<uint8_t> ConvertBufferToVector(winrt::Windows::Storage::Streams::IBuffer const& buffer)
{
    winrt::com_array<uint8_t> byteArray;
    winrt::Windows::Security::Cryptography::CryptographicBuffer::CopyToByteArray(buffer, byteArray);
    return std::vector<uint8_t>(byteArray.begin(), byteArray.end());
}

std::wstring FormatUserHelloKeyName(PCWSTR name)
{
    static constexpr wchar_t c_formatString[] = L"{}//{}//{}";
    wil::unique_handle tokenHandle;

    THROW_LAST_ERROR_IF(!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tokenHandle));

    DWORD tokenInfoLength = 0;
    GetTokenInformation(tokenHandle.get(), TokenUser, nullptr, 0, &tokenInfoLength);
    std::vector<BYTE> tokenInfoBuffer(tokenInfoLength);

    THROW_LAST_ERROR_IF(!GetTokenInformation(tokenHandle.get(), TokenUser, tokenInfoBuffer.data(), tokenInfoLength, &tokenInfoLength));

    PTOKEN_USER tokenUser = reinterpret_cast<PTOKEN_USER>(tokenInfoBuffer.data());

    // Extract the SID from the TOKEN_USER structure
    PSID userSid = tokenUser->User.Sid;  // This is how you get the SID

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

// Helper function to convert a KeyCredential to vector<uint8_t> for transmission to VTL1
std::vector<uint8_t> ConvertCredentialToVector(const KeyCredential& credential, int expectedUsageCount = 1)
{
    // Get the ABI pointer and AddRef to keep the COM object alive
    auto abi = winrt::get_abi(credential);

    // Add references based on expected Usage count
    for (int i = 0; i < expectedUsageCount; ++i)
    {
        static_cast<IUnknown*>(abi)->AddRef();
    }

    std::wcout << L"DEBUG: ConvertCredentialToVector - AddRef called " << expectedUsageCount << L" times on credential ABI: 0x" << std::hex << reinterpret_cast<uintptr_t>(abi) << std::dec << std::endl;

    uintptr_t credentialPtr = reinterpret_cast<uintptr_t>(abi);
    std::vector<uint8_t> credentialVector(sizeof(uintptr_t));
    memcpy(credentialVector.data(), &credentialPtr, sizeof(uintptr_t));
    return credentialVector;
}

veil_abi::Types::credentialAndFormattedKeyNameAndSessionInfo veil_abi::Untrusted::Implementation::userboundkey_establish_session_for_create(
    uintptr_t enclave,
    const std::wstring& key_name,
    uintptr_t ecdh_protocol,
    const std::wstring& message,
    uintptr_t window_id,
    const veil_abi::Types::keyCredentialCacheConfig& cache_config)
{
    std::wcout << L"Inside userboundkey_establish_session_for_create_callback"<< std::endl;
    auto algorithm = GetAlgorithm(ecdh_protocol);

    // Convert the cacheConfig parameter to KeyCredentialCacheConfiguration
    auto cacheConfiguration = ConvertCacheConfig(cache_config);

    auto sessionInfo = std::make_shared<uintptr_t>(0);
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
        KeyCredentialCreationOption::ReplaceExisting,
        algorithm,
        message,
        cacheConfiguration,
        static_cast<winrt::Windows::UI::WindowId>(window_id),
        ChallengeResponseKind::VirtualizationBasedSecurityEnclave,
        [sessionInfo, enclaveptr] (const auto& challenge) mutable -> winrt::Windows::Storage::Streams::IBuffer
        {            
            std::wcout << L"DEBUG: Challenge callback invoked! Challenge size: " << challenge.Length() << std::endl;
            
            try {
                auto enclaveInterface = veil_abi::Trusted::Stubs::export_interface(enclaveptr);

                std::wcout << L"DEBUG: Converting challenge buffer..." << std::endl;
                auto challengeVector = ConvertBufferToVector(challenge);
                std::wcout << L"DEBUG: Challenge vector size: " << challengeVector.size() << std::endl;

                std::wcout << L"DEBUG: About to call userboundkey_get_attestation_report..." << std::endl;
                auto attestationReportAndSessionInfo = enclaveInterface.userboundkey_get_attestation_report(challengeVector);
                std::wcout << L"DEBUG: userboundkey_get_attestation_report returned successfully!" << std::endl;

                *sessionInfo = attestationReportAndSessionInfo.sessionInfo;
                std::wcout << L"DEBUG: Session stored: " << *sessionInfo << std::endl;
            
                // Convert std::vector<uint8_t> back to IBuffer for return
                std::wcout << L"DEBUG: Converting attestation report back to IBuffer..." << std::endl;
                auto result = winrt::Windows::Security::Cryptography::CryptographicBuffer::CreateFromByteArray(attestationReportAndSessionInfo.attestationReport);
                std::wcout << L"DEBUG: Challenge callback completed successfully!" << std::endl;
                return result;
            }
            catch (const std::exception& e) {
                std::wcout << L"DEBUG: Exception in challenge callback: " << e.what() << std::endl;
                throw;
            }
            catch (...) {
                std::wcout << L"DEBUG: Unknown exception in challenge callback!" << std::endl;
                throw;
            }
        }
    ).get();

    std::wcout << L"RequestCreateAsync returned" << std::endl;

    // Check if the operation was successful
    auto status = credentialResult.Status();
    if (status != KeyCredentialStatus::Success)
    {
        THROW_HR(static_cast<HRESULT>(status));
    }

    const auto& credential = credentialResult.Credential();
    std::wstring formattedKeyName = FormatUserHelloKeyName(key_name.c_str());

    credentialAndFormattedKeyNameAndSessionInfo result;
    result.credential = ConvertCredentialToVector(credential);
    result.formattedKeyName = formattedKeyName; // Store the formatted key name
    result.sessionInfo = *sessionInfo; // Store session info

    return result;
}

// Helper function to convert vector<uint8_t> back to KeyCredential
KeyCredential ConvertVectorToCredential(const std::vector<uint8_t>& credentialVector)
{
    if (credentialVector.size() != sizeof(uintptr_t))
    {
        THROW_HR(E_INVALIDARG);
    }
    
    uintptr_t credentialPtr;
    memcpy(&credentialPtr, credentialVector.data(), sizeof(uintptr_t));
    void* abi = reinterpret_cast<void*>(credentialPtr);
    
    std::wcout << L"DEBUG: ConvertVectorToCredential - Retrieved credential ABI: 0x" << std::hex << credentialPtr << std::dec << std::endl;
    
    // Create KeyCredential and transfer ownership (this will handle the Release)
    // The take_ownership_from_abi will NOT AddRef, so our earlier AddRef is consumed
    return KeyCredential{ abi, winrt::take_ownership_from_abi };
}

veil_abi::Types::credentialAndFormattedKeyNameAndSessionInfo veil_abi::Untrusted::Implementation::userboundkey_establish_session_for_load(
    uintptr_t enclave,
    const std::wstring& key_name,
    const std::wstring& message,
    uintptr_t window_id,
    uint64_t nonce)
{
    auto sessionInfo = std::make_shared<uintptr_t>(0);
    auto enclaveptr = (void*)enclave;

    auto credentialResult = KeyCredentialManager::OpenAsync(
        key_name.c_str(),
        ChallengeResponseKind::VirtualizationBasedSecurityEnclave,
        [sessionInfo, enclaveptr] (const auto& challenge) mutable -> winrt::Windows::Storage::Streams::IBuffer
    {
        std::wcout << L"DEBUG: Load callback challenge invoked! Challenge size: " << challenge.Length() << std::endl;
        
        try {
            auto enclaveInterface = veil_abi::Trusted::Stubs::export_interface(enclaveptr);

            std::wcout << L"DEBUG: Converting challenge buffer..." << std::endl;
            auto challengeVector = ConvertBufferToVector(challenge);
            std::wcout << L"DEBUG: Challenge vector size: " << challengeVector.size() << std::endl;

            std::wcout << L"DEBUG: About to call userboundkey_get_attestation_report (load callback)..." << std::endl;
            auto attestationReportAndSessionInfo = enclaveInterface.userboundkey_get_attestation_report(challengeVector);
            std::wcout << L"DEBUG: userboundkey_get_attestation_report returned successfully (load callback)!" << std::endl;

            *sessionInfo = attestationReportAndSessionInfo.sessionInfo;

            // Convert std::vector<uint8_t> back to IBuffer for return
            return winrt::Windows::Security::Cryptography::CryptographicBuffer::CreateFromByteArray(attestationReportAndSessionInfo.attestationReport);
        }
        catch (const std::exception& e) {
            std::wcout << L"DEBUG: Exception in load callback: " << e.what() << std::endl;
            throw;
        }
        catch (...) {
            std::wcout << L"DEBUG: Unknown exception in load callback!" << std::endl;
            throw;
        }
    }
    ).get();

    // Check if the operation was successful
    auto status = credentialResult.Status();
    if (status != KeyCredentialStatus::Success)
    {
        THROW_HR(static_cast<HRESULT>(status));
    }

    const auto& credential = credentialResult.Credential();
    std::wstring formattedKeyName = FormatUserHelloKeyName(key_name.c_str());

    // Return the credential as a vector along with sessionInfo for VTL1 to use later
    credentialAndFormattedKeyNameAndSessionInfo result;
    result.credential = ConvertCredentialToVector(credential, 2); // 2 = expected usage count: one for RetrieveAuthorizationContext and one for DeriveSharedSecret in load flow
    result.formattedKeyName = formattedKeyName;
    result.sessionInfo = *sessionInfo; // Store session info    
    return result;
}

// New VTL0 function to extract authorization context from credential
std::vector<uint8_t> veil_abi::Untrusted::Implementation::userboundkey_get_authorization_context_from_credential(
    const std::vector<uint8_t>& credential_vector,
    const std::vector<uint8_t>& encrypted_kcm_request_for_get_authorization_context,
    const std::wstring& message,
    uintptr_t window_id)
{
    std::wcout << L"DEBUG: userboundkey_get_authorization_context_from_credential_callback called" << std::endl;

    KeyCredential credential{ nullptr };
    
    try
    {
        // Convert the credential vector back to KeyCredential
        credential = ConvertVectorToCredential(credential_vector);
        
        std::wcout << L"DEBUG: Converting credential vector back to KeyCredential" << std::endl;

        // Extract authorization context
        auto authorizationContext = credential.RetrieveAuthorizationContext(
            winrt::Windows::Security::Cryptography::CryptographicBuffer::CreateFromByteArray(encrypted_kcm_request_for_get_authorization_context));

        auto result = ConvertBufferToVector(authorizationContext);

        std::wcout << L"DEBUG: userboundkey_get_authorization_context_from_credential_callback completed successfully" << std::endl;
        
        // The KeyCredential destructor will automatically handle the Release when it goes out of scope
        return result;
    }
    catch (const std::exception& e)
    {
        std::wcout << L"DEBUG: Exception in userboundkey_get_authorization_context_from_credential_callback: " << e.what() << std::endl;

        // If we successfully created the credential but failed later, the destructor will clean up
        // If we failed to create the credential, there's nothing extra to clean up
        throw;
    }
    catch (...)
    {
        std::wcout << L"DEBUG: Unknown exception in userboundkey_get_authorization_context_from_credential_callback" << std::endl;
        
        // If we successfully created the credential but failed later, the destructor will clean up
        // If we failed to create the credential, there's nothing extra to clean up
        throw;
    }
}

// New VTL0 function to extract secret from credential
std::vector<uint8_t> veil_abi::Untrusted::Implementation::userboundkey_get_secret_from_credential(
    const std::vector<uint8_t>& credential_vector,
    const std::vector<uint8_t>& encrypted_kcm_request_for_derive_shared_secret,
    const std::wstring& message,
    uintptr_t window_id)
{
    std::wcout << L"DEBUG: userboundkey_get_secret_from_credential_callback called" << std::endl;

    KeyCredential credential {nullptr};

    try
    {
        // Convert the credential vector back to KeyCredential
        credential = ConvertVectorToCredential(credential_vector);

        std::wcout << L"DEBUG: Converting credential vector back to KeyCredential" << std::endl;

        // Derive shared secret. This prompts for the hello PIN.
        auto secret = credential.RequestDeriveSharedSecretAsync(
            (winrt::Windows::UI::WindowId)window_id,
            message,
            winrt::Windows::Security::Cryptography::CryptographicBuffer::CreateFromByteArray(encrypted_kcm_request_for_derive_shared_secret)).get();

        auto result = ConvertBufferToVector(secret.Result());
        std::wcout << L"DEBUG: userboundkey_get_secret_from_credential_callback completed successfully" << std::endl;

        // The KeyCredential destructor will automatically handle the Release when it goes out of scope
        return result;
    }
    catch (const std::exception& e)
    {
        std::wcout << L"DEBUG: Exception in userboundkey_get_secret_from_credential_callback: " << e.what() << std::endl;

        // If we successfully created the credential but failed later, the destructor will clean up
        // If we failed to create the credential, there's nothing extra to clean up
        throw;
    }
    catch (...)
    {
        std::wcout << L"DEBUG: Unknown exception in userboundkey_get_secret_from_credential_callback" << std::endl;

        // If we successfully created the credential but failed later, the destructor will clean up
        // If we failed to create the credential, there's nothing extra to clean up
        throw;
    }
}
