// Copyright (c) Microsoft Corporation.
//

#pragma once

#include <vector>
#include <string>

#include <veil\enclave\userboundkey.vtl1.h>

// User-bound key configuration and management functions
veil::vtl1::userboundkey::keyCredentialCacheConfig CreateSecureKeyCredentialCacheConfig();

HRESULT EnsureUserBoundKeyLoaded(
    _In_ const std::wstring& helloKeyName,
    _In_ const std::wstring& pinMessage,
    _In_ const uintptr_t windowId,
    _In_ const std::vector<std::uint8_t>& securedEncryptionKeyBytes,
    _Inout_ bool& needsReseal,
    _Out_ std::vector<std::uint8_t>& resealedEncryptionKeyBytes);

// Public API functions for user-bound key operations
namespace VbsEnclave::Trusted::Implementation
{
    HRESULT MyEnclaveCreateUserBoundKey(
        _In_ const std::wstring& helloKeyName,
        _In_ const std::wstring& pinMessage,
        _In_ const uintptr_t windowId,
        _In_ const uint32_t keyCredentialCacheOption,
        _Out_ std::vector<std::uint8_t>& securedEncryptionKeyBytes);

    HRESULT MyEnclaveLoadUserBoundKeyAndEncryptData(
        _In_ const std::wstring& helloKeyName,
        _In_ const std::wstring& pinMessage,
        _In_ const uintptr_t windowId,
        _In_ const std::vector<std::uint8_t>& securedEncryptionKeyBytes,
        _In_ const std::wstring& inputData,
        _Out_ std::vector<std::uint8_t>& combinedOutputData,
        _Out_ bool& needsReseal,
        _Out_ std::vector<std::uint8_t>& resealedEncryptionKeyBytes);

    HRESULT MyEnclaveLoadUserBoundKeyAndDecryptData(
        _In_ const std::wstring& helloKeyName,
        _In_ const std::wstring& pinMessage,
        _In_ const uintptr_t windowId,
        _In_ const std::vector<std::uint8_t>& securedEncryptionKeyBytes,
        _In_ const std::vector<std::uint8_t>& combinedInputData,
        _Out_ std::wstring& decryptedData,
        _Out_ bool& needsReseal,
        _Out_ std::vector<std::uint8_t>& resealedEncryptionKeyBytes);
}
