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
        [sessionKeyPtr, enclaveptr] (const auto& challenge) mutable -> winrt::Windows::Storage::Streams::IBuffer
        {            
            std::wcout << L"DEBUG: Challenge callback invoked! Challenge size: " << challenge.Length() << std::endl;
            
            try {
                std::wcout << L"DEBUG: Creating enclave interface..." << std::endl;
                std::wcout << L"DEBUG: Enclave pointer value: 0x" << std::hex << reinterpret_cast<uintptr_t>(enclaveptr) << std::dec << std::endl;
                
                // Validate the enclave pointer before using it
                if (enclaveptr == nullptr) {
                    std::wcout << L"DEBUG: ERROR - Enclave pointer is null!" << std::endl;
                    THROW_HR(E_INVALIDARG);
                }
                                
                // Create the enclave interface directly with the VBS enclave handle
                // The VBS Enclave framework will handle the module resolution internally
                auto enclaveInterface = veil_abi::VTL0_Stubs::export_interface(enclaveptr);
                
                std::wcout << L"DEBUG: Registering VTL0 callbacks..." << std::endl;
                HRESULT hr = enclaveInterface.RegisterVtl0Callbacks();
                if (FAILED(hr)) {
                    std::wcout << L"DEBUG: RegisterVtl0Callbacks failed with HRESULT: 0x" << std::hex << hr << std::endl;
                    THROW_HR(hr);
                }
                std::wcout << L"DEBUG: VTL0 callbacks registered successfully!" << std::endl;
                
                std::wcout << L"DEBUG: Converting challenge buffer..." << std::endl;
                auto challengeVector = ConvertBufferToVector(challenge);
                std::wcout << L"DEBUG: Challenge vector size: " << challengeVector.size() << std::endl;
                
                std::wcout << L"DEBUG: About to call userboundkey_get_attestation_report..." << std::endl;
                auto attestationReportAndSessionKeyPtr = enclaveInterface.userboundkey_get_attestation_report(challengeVector);
                std::wcout << L"DEBUG: userboundkey_get_attestation_report returned successfully!" << std::endl;
                
                *sessionKeyPtr = attestationReportAndSessionKeyPtr.sessionKeyPtr;
                std::wcout << L"DEBUG: Session key stored: " << *sessionKeyPtr << std::endl;
            
                // Convert std::vector<uint8_t> back to IBuffer for return
                std::wcout << L"DEBUG: Converting attestation report back to IBuffer..." << std::endl;
                auto result = winrt::Windows::Security::Cryptography::CryptographicBuffer::CreateFromByteArray(attestationReportAndSessionKeyPtr.attestationReport);
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
        [sessionKeyPtr] (const auto& challenge) mutable -> winrt::Windows::Storage::Streams::IBuffer
    {
        std::wcout << L"DEBUG: Load callback challenge invoked! Challenge size: " << challenge.Length() << std::endl;
        
        try {
            auto enclaveInterface = veil_abi::VTL0_Stubs::export_interface(nullptr);
            
            std::wcout << L"DEBUG: WARNING - Using nullptr for enclave in load callback!" << std::endl;
            std::wcout << L"DEBUG: Skipping RegisterVtl0Callbacks for load callback due to null enclave..." << std::endl;
            
            auto challengeVector = ConvertBufferToVector(challenge);
            
            std::wcout << L"DEBUG: About to call userboundkey_get_attestation_report (load callback)..." << std::endl;
            auto attestationReportAndSessionKeyPtr = enclaveInterface.userboundkey_get_attestation_report(challengeVector);
            std::wcout << L"DEBUG: userboundkey_get_attestation_report returned successfully (load callback)!" << std::endl;
            
            *sessionKeyPtr = attestationReportAndSessionKeyPtr.sessionKeyPtr;
            
            // Convert std::vector<uint8_t> back to IBuffer for return
            return winrt::Windows::Security::Cryptography::CryptographicBuffer::CreateFromByteArray(attestationReportAndSessionKeyPtr.attestationReport);
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
