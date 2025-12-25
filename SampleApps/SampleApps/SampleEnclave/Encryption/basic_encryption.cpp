// Copyright (c) Microsoft Corporation.
//

#include <pch.h>
#include "basic_encryption.h"
#include "..\Common\globals.h"

#include <veil\enclave\crypto.vtl1.h>
#include <veil\enclave\logger.vtl1.h>
#include <veil\enclave\vtl0_functions.vtl1.h>
#include <VbsEnclave\Enclave\Implementation\Types.h>

using namespace veil::vtl1::vtl0_functions;

//
// Secured encryption key creation
//
HRESULT VbsEnclave::Trusted::Implementation::RunEncryptionKeyExample_CreateEncryptionKey(
    _In_ const std::uint32_t activity_level, 
    _In_ const std::wstring& logFilePath, 
    _Out_ std::vector<std::uint8_t>& securedEncryptionKeyBytes)
{
    auto activityLevel = (veil::any::logger::eventLevel)activity_level;

    veil::vtl1::logger::add_log_from_enclave(
        L"[Enclave] In RunEncryptionKeyExample_CreateEncryptionKeyImpl", 
        veil::any::logger::eventLevel::EVENT_LEVEL_CRITICAL,
        activityLevel,
        logFilePath);

    debug_print("");
    debug_print(L"[Create flow]");
    debug_print("");
    veil::vtl1::logger::add_log_from_enclave(
        L"[Enclave] Create flow", 
        veil::any::logger::eventLevel::EVENT_LEVEL_VERBOSE,
        activityLevel,
        logFilePath);
    
    debug_print("");

    // Generate our encryption key
    debug_print(L"1. Generating our encryption key");
    veil::vtl1::logger::add_log_from_enclave(
        L"[Enclave] Generating our encryption key",
        veil::any::logger::eventLevel::EVENT_LEVEL_INFO,
        activityLevel,
        logFilePath);
    auto encryptionKeyBytes = veil::vtl1::crypto::generate_symmetric_key_bytes();
    debug_print(L" ...CHECKPOINT: encryption key byte count: %d", encryptionKeyBytes.size());
    std::wstring logSizeStr = std::to_wstring(encryptionKeyBytes.size());
    veil::vtl1::logger::add_log_from_enclave(
        L"[Enclave] Encryption key byte count: " + logSizeStr,
        veil::any::logger::eventLevel::EVENT_LEVEL_CRITICAL,
        activityLevel,
        logFilePath);
    debug_print("");
    
    // Seal the key using enclave sealing policy
    debug_print(L"4. Sealing the serialized key material for our enclave only");
    veil::vtl1::logger::add_log_from_enclave(
        L"[Enclave] Sealing the serialized key material for our enclave only",
        veil::any::logger::eventLevel::EVENT_LEVEL_INFO,
        activityLevel,
        logFilePath);

    // Seal the key using enclave sealing policy
    auto sealedKeyMaterial = veil::vtl1::crypto::seal_data(encryptionKeyBytes, ENCLAVE_IDENTITY_POLICY_SEAL_SAME_IMAGE, g_runtimePolicy);
    debug_print(L" ...CHECKPOINT: sealed key material byte count: %d", sealedKeyMaterial.size());
    logSizeStr = std::to_wstring(sealedKeyMaterial.size());
    veil::vtl1::logger::add_log_from_enclave(
        L"[Enclave] Sealed key material byte count: " + logSizeStr,
        veil::any::logger::eventLevel::EVENT_LEVEL_CRITICAL,
        activityLevel,
        logFilePath);
    debug_print("");

    // Erase our plain-text encryption key, (not necessary, but being explicit that we do not need this data anymore)
    encryptionKeyBytes.fill(0);

    // Return the secured encryption key to vtl0 host caller...
    securedEncryptionKeyBytes.assign(sealedKeyMaterial.begin(), sealedKeyMaterial.end());

    return S_OK;
}

// Internal implementation function for common encryption/decryption logic
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
    _In_ bool calledFromThreadpool,
    _In_ std::wstring logPrefix,
    _Inout_opt_ std::vector<std::uint8_t>* threadpool_encryptedInputBytes,
    _Inout_opt_ std::vector<std::uint8_t>* threadpool_encryptionTag,
    _Inout_opt_ std::wstring* threadpool_decryptedInputBytes)
{
    auto activityLevel = (veil::any::logger::eventLevel)activity_level;

    veil::vtl1::logger::add_log_from_enclave(
        L"[Enclave] In RunEncryptionKeyExample_LoadEncryptionKeyImpl",
        veil::any::logger::eventLevel::EVENT_LEVEL_CRITICAL,
        activityLevel,
        logFilePath);

    debug_print("%ws", logPrefix.c_str());
    debug_print("");
    debug_print(L"[Load flow]");
    debug_print("");

    debug_print("%ws", logPrefix.c_str());
    debug_print(L"1. Unsealing our encryption key (only our enclave can succeed this operation)");
    auto [unsealedBytes, unsealingFlags] = veil::vtl1::crypto::unseal_data(securedEncryptionKeyBytes);
    debug_print("%ws", logPrefix.c_str());
    debug_print(L" ...CHECKPOINT: unsealed byte count: = %d", unsealedBytes.size());
    debug_print("");

    // Create the symmetric key from unsealed bytes
    auto encryptionKey = veil::vtl1::crypto::create_symmetric_key(unsealedBytes);

   if (isToBeEncrypted)
   {
       // Encrypt the user input data
       auto const SOME_PLAIN_TEXT = dataToEncrypt.c_str();

       debug_print("%ws", logPrefix.c_str());
       debug_print(L"2. Encrypting input text.");
       auto [encryptedText, encryptionTag] = veil::vtl1::crypto::encrypt(encryptionKey.get(), veil::vtl1::as_data_span(SOME_PLAIN_TEXT), veil::vtl1::crypto::zero_nonce);
       debug_print("%ws", logPrefix.c_str());
       debug_print(L" ...CHECKPOINT: encrypted text's byte count: = %d", encryptedText.size());
       debug_print("");

       if (!calledFromThreadpool)
       {
           // Return the encrypted input to vtl0 host caller...
           encryptedInputBytes.assign(encryptedText.begin(), encryptedText.end());
           tag.assign(encryptionTag.begin(), encryptionTag.end());
       }
       else
       {
           // Return the encrypted input to vtl0 host caller...
           threadpool_encryptedInputBytes->assign(encryptedText.begin(), encryptedText.end());
           threadpool_encryptionTag->assign(encryptionTag.begin(), encryptionTag.end());
       }
   }
   else
   {
       // Decrypt the stored encrypted input
       debug_print("%ws", logPrefix.c_str());
       debug_print(L"3. Decrypting text...");
       auto decryptedText = veil::vtl1::crypto::decrypt(encryptionKey.get(), encryptedInputBytes, veil::vtl1::crypto::zero_nonce, tag);
       std::wstring decryptedString = veil::vtl1::to_wstring(decryptedText);
       debug_print("%ws", logPrefix.c_str());
       debug_print(L" ...CHECKPOINT: decrypted text: = %ws", decryptedString.c_str());
       debug_print("");

       if (!calledFromThreadpool)
       {
           // Return the decrypted input to vtl0 host caller...
           decryptedInputBytes = decryptedString;
       }
       else
       {
           // Return the decrypted input to vtl0 host caller...
           *threadpool_decryptedInputBytes = decryptedString;
       }
   }

   return S_OK;
}

//
// Load encryption key and encrypt data
//
HRESULT VbsEnclave::Trusted::Implementation::RunEncryptionKeyExample_LoadEncryptionKeyAndEncrypt(
    _In_ const std::vector<std::uint8_t>& securedEncryptionKeyBytes,
    _In_ const std::wstring& dataToEncrypt,
    _In_ const std::uint32_t activity_level,
    _In_ const std::wstring& logFilePath,
    _Out_ std::vector<std::uint8_t>& resealedEncryptionKeyBytes,
    _Out_ std::vector<std::uint8_t>& encryptedInputBytes,
    _Out_ std::vector<std::uint8_t>& tag)
{
    std::wstring decryptedInputBytes; // Unused in encryption flow
    RETURN_IF_FAILED(RunEncryptionKeyExample_LoadEncryptionKeyImpl(
        securedEncryptionKeyBytes,
        dataToEncrypt,
        true, // isToBeEncrypted = true for encryption
        activity_level,
        logFilePath,
        resealedEncryptionKeyBytes,
        encryptedInputBytes,
        tag,
        decryptedInputBytes
        ));
    return S_OK;
}

//
// Load encryption key and decrypt data
//
HRESULT VbsEnclave::Trusted::Implementation::RunEncryptionKeyExample_LoadEncryptionKeyAndDecrypt(
    _In_ const std::vector<std::uint8_t>& securedEncryptionKeyBytes,
    _In_ const std::uint32_t activity_level,
    _In_ const std::wstring& logFilePath,
    _In_ const std::vector<std::uint8_t>& encryptedInputBytes,
    _In_ const std::vector<std::uint8_t>& tag,
    _Out_ std::vector<std::uint8_t>& resealedEncryptionKeyBytes,
    _Out_ std::wstring& decryptedInputBytes)
{
    std::wstring dataToEncrypt; // Unused in decryption flow
    std::vector<std::uint8_t> localEncryptedInputBytes = encryptedInputBytes;
    std::vector<std::uint8_t> localTag = tag;
    
    RETURN_IF_FAILED(RunEncryptionKeyExample_LoadEncryptionKeyImpl(
        securedEncryptionKeyBytes,
        dataToEncrypt,
        false, // isToBeEncrypted = false for decryption
        activity_level,
        logFilePath,
        resealedEncryptionKeyBytes,
        localEncryptedInputBytes,
        localTag,
        decryptedInputBytes
        ));
    return S_OK;
}
