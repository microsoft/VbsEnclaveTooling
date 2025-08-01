#pragma once

#include <functional>
#include <future>
#include <string>
#include <tuple>
#include <vector>
#include <memory>
#include <winrt/base.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Security.Credentials.h>
#include <winrt/Windows.Security.Cryptography.h>
#include <winrt/Windows.Security.Cryptography.Certificates.h>
#include <winrt/Windows.Storage.Streams.h>

#include <VbsEnclave\HostApp\Stubs.h>

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

authContextBlobAndSessionKeyPtr veil_abi::VTL0_Stubs::export_interface::userboundkey_establish_session_for_create_callback(
    const std::wstring& key_name,
    uintptr_t ecdhAlgorithm,
    const std::wstring& message,
    uintptr_t windowId)
{
    auto algorithm = GetAlgorithm(ecdhAlgorithm);

    winrt::Windows::Foundation::TimeSpan timeout = winrt::Windows::Foundation::TimeSpan {3000000000};   // 5 mins
    auto cacheConfiguration = KeyCredentialCacheConfiguration(
        KeyCredentialCacheOption::NoCache,
        timeout, // KeyCredentialCacheTimeout
        5); // KeyCredentialCacheUsageCount

    auto sessionKeyPtr = std::make_shared<uintptr_t>(0);
    
    auto credentialResult = KeyCredentialManager::RequestCreateAsync(
        key_name,
        KeyCredentialCreationOption::FailIfExists,
        algorithm,
        message,
        cacheConfiguration,
        (winrt::Windows::UI::WindowId)windowId,
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

    authContextBlobAndSessionKeyPtr result;

    auto authContextBuffer = credential.RetrieveAuthorizationContext();
    result.authContextBlob = ConvertBufferToVector(authContextBuffer);
    result.sessionKeyPtr = *sessionKeyPtr;

    return result;
}

secretAndAuthorizationContextAndSessionKeyPtr veil_abi::VTL0_Stubs::export_interface::userboundkey_establish_session_for_load_callback(
    const std::wstring& key_name,
    const std::vector<uint8_t>& publicKeyBytes,
    const std::wstring& message,
    uintptr_t windowId)
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
        (winrt::Windows::UI::WindowId)windowId, 
        message, 
        winrt::Windows::Security::Cryptography::CryptographicBuffer::CreateFromByteArray(publicKeyBytes)).get();
    
    secretAndAuthorizationContextAndSessionKeyPtr result;
    result.secret = ConvertBufferToVector(secret.Result());
    result.authorizationContext = ConvertBufferToVector(authorizationContext);
    result.sessionKeyPtr = *sessionKeyPtr;
    return result;
}
