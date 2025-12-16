// Copyright (c) Microsoft Corporation.
//

#pragma once

#include <vector>
#include <string>

// Public API functions for basic encryption operations
namespace VbsEnclave::Trusted::Implementation
{
    HRESULT RunEncryptionKeyExample_CreateEncryptionKey(
        _In_ const std::uint32_t activity_level,
        _In_ const std::wstring& logFilePath,
        _Out_ std::vector<std::uint8_t>& securedEncryptionKeyBytes);

    HRESULT RunEncryptionKeyExample_LoadEncryptionKeyAndEncrypt(
        _In_ const std::vector<std::uint8_t>& securedEncryptionKeyBytes,
        _In_ const std::wstring& dataToEncrypt,
        _In_ const std::uint32_t activity_level,
        _In_ const std::wstring& logFilePath,
        _Out_ std::vector<std::uint8_t>& resealedEncryptionKeyBytes,
        _Out_ std::vector<std::uint8_t>& encryptedInputBytes,
        _Out_ std::vector<std::uint8_t>& tag);

    HRESULT RunEncryptionKeyExample_LoadEncryptionKeyAndDecrypt(
        _In_ const std::vector<std::uint8_t>& securedEncryptionKeyBytes,
        _In_ const std::uint32_t activity_level,
        _In_ const std::wstring& logFilePath,
        _In_ const std::vector<std::uint8_t>& encryptedInputBytes,
        _In_ const std::vector<std::uint8_t>& tag,
        _Out_ std::vector<std::uint8_t>& resealedEncryptionKeyBytes,
        _Out_ std::wstring& decryptedInputBytes);
}

// Internal helper function for common encryption/decryption logic
HRESULT RunEncryptionKeyExample_LoadEncryptionKeyImpl(
    _In_ const std::vector<std::uint8_t>& securedEncryptionKeyBytes,
    _In_ const std::wstring& dataToEncrypt,
    _In_ const bool isToBeEncrypted,
    _In_ const std::uint32_t activity_level,
    _In_ const std::wstring& logFilePath,
    _Out_ std::vector<std::uint8_t>& resealedEncryptionKeyBytes,
    _Out_ std::vector<std::uint8_t>& encryptedInputBytes,
    _Out_ std::vector<std::uint8_t>& tag,
    _Out_ std::wstring& decryptedInputBytes,
    _In_ bool calledFromThreadpool = false,
    _In_ std::wstring logPrefix = L"",
    _Inout_opt_ std::vector<std::uint8_t>* threadpool_encryptedInputBytes = nullptr,
    _Inout_opt_ std::vector<std::uint8_t>* threadpool_encryptionTag = nullptr,
    _Inout_opt_ std::wstring* threadpool_decryptedInputBytes = nullptr);
