// Copyright (c) Microsoft Corporation.
//

#pragma once

#include <vector>
#include <string>

#include <veil\enclave\userboundkey.vtl1.h>
#include <veil\enclave\crypto.vtl1.h>

// User-bound key configuration and management functions for asymmetric keys
veil::vtl1::userboundkey::keyCredentialCacheConfig CreateSecureKeyCredentialCacheConfigForSignature();

HRESULT EnsureUserBoundPrivateKeyLoaded(
    _In_ const std::wstring& helloKeyName,
    _In_ const std::wstring& pinMessage,
    _In_ const uintptr_t windowId,
    _In_ const std::vector<std::uint8_t>& securedPrivateKeyBytes,
    _Inout_ bool& needsReseal,
    _Out_ std::vector<std::uint8_t>& resealedPrivateKeyBytes);

// Public API functions for user-bound asymmetric key operations
namespace VbsEnclave::Trusted::Implementation
{
    HRESULT MyEnclaveCreateUserBoundAsymmetricKey(
        _In_ const std::wstring& helloKeyName,
        _In_ const std::wstring& pinMessage,
        _In_ const uintptr_t windowId,
        _In_ const uint32_t keyCredentialCreationOption,
        _Out_ std::vector<std::uint8_t>& securedPrivateKeyBytes,
        _Out_ std::vector<std::uint8_t>& publicKeyBytes);

    HRESULT MyEnclaveLoadUserBoundKeyAndSign(
        _In_ const std::wstring& helloKeyName,
        _In_ const std::wstring& pinMessage,
        _In_ const uintptr_t windowId,
        _In_ const std::vector<std::uint8_t>& securedPrivateKeyBytes,
        _In_ const std::wstring& inputData,
        _Out_ std::vector<std::uint8_t>& signatureData,
        _Out_ bool& needsReseal,
        _Out_ std::vector<std::uint8_t>& resealedPrivateKeyBytes);

    HRESULT MyEnclaveVerifySignature(
        _In_ const std::vector<std::uint8_t>& publicKeyBytes,
        _In_ const std::wstring& inputData,
        _In_ const std::vector<std::uint8_t>& signatureData,
        _Out_ bool& isValid);
}
