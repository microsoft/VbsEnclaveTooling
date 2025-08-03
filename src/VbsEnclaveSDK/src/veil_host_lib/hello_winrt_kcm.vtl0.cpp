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

#include <winrt/base.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Security.Credentials.h>
#include <winrt/Windows.Security.Cryptography.h>
#include <winrt/Windows.Security.Cryptography.Certificates.h>
#include <winrt/Windows.Storage.Streams.h>

#include <VbsEnclave\HostApp\Stubs.h>
#include "..\veil_enclave_lib\vengcdll.h"
#include <VbsEnclave\HostApp\DeveloperTypes.h>

using namespace winrt::Windows::Security::Credentials;

// Helper function to convert WinRT IBuffer to std::vector<uint8_t>
std::vector<uint8_t> ConvertBufferToVector(winrt::Windows::Storage::Streams::IBuffer const& buffer)
{
    winrt::com_array<uint8_t> byteArray;
    winrt::Windows::Security::Cryptography::CryptographicBuffer::CopyToByteArray(buffer, byteArray);
    return std::vector<uint8_t>(byteArray.begin(), byteArray.end());
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

// Helper function to convert DeveloperTypes::keyCredentialCacheConfig to KeyCredentialCacheConfiguration
KeyCredentialCacheConfiguration ConvertCacheConfig(const DeveloperTypes::keyCredentialCacheConfig& cacheConfig)
{
    // Map cacheOption to KeyCredentialCacheOption
    KeyCredentialCacheOption cacheOption;
    switch (cacheConfig.cacheOption)
    {
        case 1:
            cacheOption = KeyCredentialCacheOption::NoCache;
            break;
        case 2:
            cacheOption = KeyCredentialCacheOption::CacheWhenUnlocked;
            break;
        case 4:
            cacheOption = KeyCredentialCacheOption::CacheUnderLock;
            break;
        default:
            cacheOption = KeyCredentialCacheOption::NoCache; // Default fallback
            break;
    }

    // Convert timeout from seconds to TimeSpan (100-nanosecond units)
    winrt::Windows::Foundation::TimeSpan timeout{ static_cast<int64_t>(cacheConfig.cacheTimeoutInSeconds) * 10000000LL };

    // Use RoGetActivationFactory to get the factory for KeyCredentialCacheConfiguration
    winrt::com_ptr<winrt::Windows::Security::Credentials::IKeyCredentialCacheConfigurationFactory> factory;

    // Create HSTRING for the runtime class name
    winrt::hstring className = L"Windows.Security.Credentials.KeyCredentialCacheConfiguration";

    // Get the activation factory using RoGetActivationFactory
    HRESULT hr = RoGetActivationFactory(
        reinterpret_cast<HSTRING>(winrt::get_abi(className)),
        winrt::guid_of<winrt::Windows::Security::Credentials::IKeyCredentialCacheConfigurationFactory>(),
        factory.put_void());

    if (SUCCEEDED(hr))
    {
        winrt::com_ptr<winrt::Windows::Security::Credentials::IKeyCredentialCacheConfiguration> instance;
        hr = factory->CreateInstance(
            static_cast<int32_t>(cacheOption),
            winrt::get_abi(timeout),
            cacheConfig.cacheUsageCount,
            reinterpret_cast<void**>(instance.put()));

        return winrt::Windows::Security::Credentials::KeyCredentialCacheConfiguration {
                    instance.detach(), winrt::take_ownership_from_abi
        };
    }

    // If RoGetActivationFactory fails, throw an exception
    THROW_HR(hr);

}

authContextBlobAndSessionKeyPtr veil_abi::VTL0_Stubs::export_interface::userboundkey_establish_session_for_create_callback(
    uintptr_t enclave,
    const std::wstring& key_name,
    uintptr_t ecdh_protocol,
    const std::wstring& message,
    uintptr_t window_id,
    const DeveloperTypes::keyCredentialCacheConfig& cache_config)
{
    std::wcout << L"Inside userboundkey_establish_session_for_create_callback"<< std::endl;
    auto algorithm = GetAlgorithm(ecdh_protocol);

    // Convert the cacheConfig parameter to KeyCredentialCacheConfiguration
    auto cacheConfiguration = ConvertCacheConfig(cache_config);

    auto sessionKeyPtr = std::make_shared<uintptr_t>(0);
    auto enclaveptr = (void*)enclave;
    
    std::wcout << L"Calling RequestCreateAsync" << std::endl;
    auto credentialResult = KeyCredentialManager::RequestCreateAsync(
        key_name,
        KeyCredentialCreationOption::FailIfExists,
        algorithm,
        message,
        cacheConfiguration,
        (winrt::Windows::UI::WindowId)window_id,
        ChallengeResponseKind::VirtualizationBasedSecurityEnclave,
        [sessionKeyPtr, enclaveptr] (const auto& challenge) mutable
        {            
            auto enclaveInterface = veil_abi::VTL0_Stubs::export_interface(enclaveptr);
            auto attestationReportAndSessionKeyPtr = enclaveInterface.userboundkey_get_attestation_report(
                ConvertBufferToVector(challenge));  // !!! call into enclave !!!
            *sessionKeyPtr = attestationReportAndSessionKeyPtr.sessionKeyPtr;
        
            // Convert std::vector<uint8_t> back to IBuffer for return
            return winrt::Windows::Security::Cryptography::CryptographicBuffer::CreateFromByteArray(attestationReportAndSessionKeyPtr.attestationReport);
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

    authContextBlobAndSessionKeyPtr result;

    auto authContextBuffer = credential.RetrieveAuthorizationContext();
    result.authContextBlob = ConvertBufferToVector(authContextBuffer);
    result.sessionKeyPtr = *sessionKeyPtr;

    return result;
}

secretAndAuthorizationContextAndSessionKeyPtr veil_abi::VTL0_Stubs::export_interface::userboundkey_establish_session_for_load_callback(
    const std::wstring& key_name,
    const std::vector<uint8_t>& public_key,
    const std::wstring& message,
    uintptr_t window_id)
{
    auto sessionKeyPtr = std::make_shared<uintptr_t>(0);
    auto credentialResult = KeyCredentialManager::OpenAsync(
        key_name.c_str(),
        ChallengeResponseKind::VirtualizationBasedSecurityEnclave,
        [sessionKeyPtr] (const auto& challenge) mutable
    {
        auto enclaveInterface = veil_abi::VTL0_Stubs::export_interface(nullptr);
        auto attestationReportAndSessionKeyPtr = enclaveInterface.userboundkey_get_attestation_report(
            ConvertBufferToVector(challenge));  // !!! call into enclave !!!
        *sessionKeyPtr = attestationReportAndSessionKeyPtr.sessionKeyPtr;
        
        // Convert std::vector<uint8_t> back to IBuffer for return
        return winrt::Windows::Security::Cryptography::CryptographicBuffer::CreateFromByteArray(attestationReportAndSessionKeyPtr.attestationReport);
    }
    ).get();

    // Check if the operation was successful
    auto status = credentialResult.Status();
    if (status != KeyCredentialStatus::Success)
    {
        THROW_HR(static_cast<HRESULT>(status));
    }

    const auto& credential = credentialResult.Credential();

    auto authorizationContext = credential.RetrieveAuthorizationContext();
    auto secret = credential.RequestDeriveSharedSecretAsync(
        (winrt::Windows::UI::WindowId)window_id, 
        message, 
        winrt::Windows::Security::Cryptography::CryptographicBuffer::CreateFromByteArray(public_key)).get();

    secretAndAuthorizationContextAndSessionKeyPtr result;
    result.secret = ConvertBufferToVector(secret.Result());
    result.authorizationContext = ConvertBufferToVector(authorizationContext);
    result.sessionKeyPtr = *sessionKeyPtr;
    return result;
}
