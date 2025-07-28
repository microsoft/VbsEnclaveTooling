#pragma once

#include <functional>
#include <future>
#include <string>
#include <tuple>
#include <vector>
#include <memory>
#include <winrt/base.h>

#include <VbsEnclave\HostApp\Stubs.h>

#include "keycredentialmanager.vtl0.h"

winrt::hstring GetAlgorithm(uintptr_t ecdhAlgorithm)
{
    if (reinterpret_cast<BCRYPT_ALG_HANDLE>(ecdhAlgorithm) == BCRYPT_ECDH_P384_ALG_HANDLE)
    {
        return KeyAlgorithmNames::Ecdh384;
    }
    else if (reinterpret_cast<BCRYPT_ALG_HANDLE>(ecdhAlgorithm) == BCRYPT_ECDH_P256_ALG_HANDLE)
    {
        return KeyAlgorithmNames::Ecdh256;
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
    auto credentialResult = winrt::Windows::Security::Credentials::KeyCredentialManager::RequestCreateAsync(
        key_name,
        KeyCredentialCreationOption::FailIfExists,
        algorithm,
        message,
        cacheConfiguration,
        (winrt::Windows::UI::WindowId)windowId,
        winrt::Windows::Security::Credentials::ChallengeResponseKind::VirtualizationBasedSecurityEnclave,
        [sessionKeyPtr] (const auto& challenge) mutable
    {
        auto enclaveInterface = veil_abi::VTL0_Stubs::export_interface(nullptr);
        auto attestationReportAndSessionKeyPtr = enclaveInterface.userboundkey_get_attestation_report(challenge);  // !!! call into enclave !!!
        *sessionKeyPtr = attestationReportAndSessionKeyPtr.sessionKeyPtr;
        return attestationReportAndSessionKeyPtr.attestationReport;
    }
    ).get();

    // Check if the operation was successful
    auto status = credentialResult.GetStatus();
    if (!SUCCEEDED(status))
    {
        THROW_HR(status);
    }

    const auto& credential = credentialResult.GetCredential();

    authContextBlobAndSessionKeyPtr result;
    result.authContextBlob = credential.RetrieveAuthorizationContext();
    result.sessionKeyPtr = *sessionKeyPtr;
    return result;
}

secretAndAuthorizationContextAndSessionKeyPtr veil_abi::VTL0_Stubs::export_interface::userboundkey_establish_session_for_load_callback(
    const std::wstring& key_name,
    const std::vector<uint8_t>& ephemeralPublicKeyBytes,
    const std::wstring& message,
    uintptr_t windowId)
{
    auto sessionKeyPtr = std::make_shared<uintptr_t>(0);
    auto credentialResult = winrt::Windows::Security::Credentials::KeyCredentialManager::OpenAsync(
        key_name.c_str(),
        winrt::Windows::Security::Credentials::ChallengeResponseKind::VirtualizationBasedSecurityEnclave,
        [sessionKeyPtr] (const auto& challenge) mutable
    {
        auto enclaveInterface = veil_abi::VTL0_Stubs::export_interface(nullptr);
        auto attestationReportAndSessionKeyPtr = enclaveInterface.userboundkey_get_attestation_report(challenge);  // !!! call into enclave !!!
        *sessionKeyPtr = attestationReportAndSessionKeyPtr.sessionKeyPtr;
        return attestationReportAndSessionKeyPtr.attestationReport;
    }
    ).get();

    // Check if the operation was successful
    auto status = credentialResult.GetStatus();
    if (!SUCCEEDED(status))
    {
        THROW_HR(status);
    }

    const auto& credential = credentialResult.GetCredential();

    auto authorizationContext = credential.RetrieveAuthorizationContext();
    auto secret = credential.RequestDeriveSharedSecretAsync(message, ephemeralPublicKeyBytes, (winrt::Windows::UI::WindowId)windowId).get();

    secretAndAuthorizationContextAndSessionKeyPtr result;
    result.secret = secret;
    result.authorizationContext = authorizationContext;
    result.sessionKeyPtr = *sessionKeyPtr;
    return result;
}
