// Copyright (c) Microsoft Corporation.
//

#pragma once

#include <vector>
#include <string>

// Public API functions for threaded encryption operations
namespace VbsEnclave::Trusted::Implementation
{
    HRESULT RunEncryptionKeyExample_LoadEncryptionKeyAndEncryptThreadpool(
        _In_ const std::vector<std::uint8_t>& securedEncryptionKeyBytes,
        _In_ const std::wstring& dataToEncrypt1,
        _In_ const std::wstring& dataToEncrypt2,
        _In_ const std::uint32_t activity_level,
        _In_ const std::wstring& logFilePath,
        _Out_ std::vector<std::uint8_t>& resealedEncryptionKeyBytes,
        _Out_ std::vector<std::uint8_t>& encryptedInputBytes1,
        _Out_ std::vector<std::uint8_t>& encryptedInputBytes2,
        _Out_ std::vector<std::uint8_t>& tag1,
        _Out_ std::vector<std::uint8_t>& tag2);

    HRESULT RunEncryptionKeyExample_LoadEncryptionKeyAndDecryptThreadpool(
        _In_ const std::vector<std::uint8_t>& securedEncryptionKeyBytes,
        _In_ const std::uint32_t activity_level,
        _In_ const std::wstring& logFilePath,
        _In_ const std::vector<std::uint8_t>& encryptedInputBytes1,
        _In_ const std::vector<std::uint8_t>& encryptedInputBytes2,
        _In_ const std::vector<std::uint8_t>& tag1,
        _In_ const std::vector<std::uint8_t>& tag2,
        _Out_ std::vector<std::uint8_t>& resealedEncryptionKeyBytes,
        _Out_ std::wstring& decryptedInputBytes1,
        _Out_ std::wstring& decryptedInputBytes2);
}
