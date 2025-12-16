// Copyright (c) Microsoft Corporation.
//

#include "../pch.h"
#include "userbound_keys.h"
#include "..\Common\globals.h"

#include <veil\enclave\crypto.vtl1.h>
#include <veil\enclave\vtl0_functions.vtl1.h>
#include <VbsEnclave\Enclave\Implementation\Types.h>

using namespace veil::vtl1::vtl0_functions;

// VTL1 function to create secure cache configuration
// This ensures VTL0 has no influence over cache configuration values
veil::vtl1::userboundkey::keyCredentialCacheConfig CreateSecureKeyCredentialCacheConfig()
{
    veil::vtl1::userboundkey::keyCredentialCacheConfig secureConfig;
    
    // VTL1 sets secure cache configuration values
    // VTL0 cannot influence these security-critical settings
    secureConfig.cacheOption = 0; // NoCache - most secure option
    secureConfig.cacheTimeoutInSeconds = 0; // No timeout when not caching
    secureConfig.cacheUsageCount = 0; // No usage count when not caching
    
    return secureConfig;
}

// Helper function to ensure user-bound key is loaded
// Handles initial load attempt and optional reseal if needed
HRESULT EnsureUserBoundKeyLoaded(
    _In_ const std::wstring& helloKeyName,
    _In_ const std::wstring& pinMessage,
    _In_ const uintptr_t windowId,
    _In_ const std::vector<std::uint8_t>& securedEncryptionKeyBytes,
    _Inout_ bool& needsReseal,
    _Out_ std::vector<std::uint8_t>& resealedEncryptionKeyBytes)
{
    // Only load the user-bound key if it's not already loaded
    if (!IsUBKLoaded())
    {
        debug_print(L"UBK not loaded, loading user-bound key");

        // VTL1 creates secure cache configuration - VTL0 input is ignored
        auto secureConfig = CreateSecureKeyCredentialCacheConfig();

        debug_print(L"Created secure cache configuration in VTL1");

        std::vector<std::uint8_t> loadedKeyBytes;
        bool loadSucceeded = false;

        // First attempt to load the user-bound key
        try
        {
            loadedKeyBytes = veil::vtl1::userboundkey::load_user_bound_key(
                helloKeyName,
                secureConfig,
                pinMessage,
                windowId,
                securedEncryptionKeyBytes,
                needsReseal);
            loadSucceeded = true;
            debug_print(L"Successfully loaded user-bound key on first attempt");
        }
        catch (...)
        {
            debug_print(L"First load attempt failed, checking if reseal is needed");
            loadSucceeded = false;
        }

        // If load failed and reseal is needed, attempt reseal and retry
        if (!loadSucceeded && needsReseal)
        {
            debug_print(L"Attempting to reseal user-bound key");
      
            try
            {
                auto resealedBytes = veil::vtl1::userboundkey::reseal_user_bound_key(
                    securedEncryptionKeyBytes,
                    ENCLAVE_SEALING_IDENTITY_POLICY::ENCLAVE_IDENTITY_POLICY_SEAL_SAME_IMAGE,
                    g_runtimePolicy);

                debug_print(L"Reseal completed, attempting to load with resealed key");

                // Store resealed bytes in output parameter
                resealedEncryptionKeyBytes.assign(resealedBytes.begin(), resealedBytes.end());

                // Reset needsReseal for the retry
                needsReseal = false;

                // Retry loading with resealed bytes
                loadedKeyBytes = veil::vtl1::userboundkey::load_user_bound_key(
                    helloKeyName,
                    secureConfig,
                    pinMessage,
                    windowId,
                    resealedBytes,
                    needsReseal);

                loadSucceeded = true;
                debug_print(L"Successfully loaded user-bound key after reseal");
            }
            catch (...)
            {
                debug_print(L"Failed to reseal or load after reseal");
                throw;
            }
        }
        else if (!loadSucceeded)
        {
            debug_print(L"Load failed and reseal not needed or not indicated");
            throw; // Re-throw the original exception
        }

        // NOW we can create a symmetric key from the loaded raw key material
        auto newEncryptionKey = veil::vtl1::crypto::create_symmetric_key(loadedKeyBytes);
        SetEncryptionKey(std::move(newEncryptionKey));
        debug_print(L"Created symmetric key from loaded user-bound key material");
    }
    else
    {
        debug_print(L"UBK already loaded, using cached key");
    }

    return S_OK;
}

//
// User bound encryption key
//
HRESULT VbsEnclave::Trusted::Implementation::MyEnclaveCreateUserBoundKey(
    _In_ const std::wstring& helloKeyName,
    _In_ const std::wstring& pinMessage,
    _In_ const uintptr_t windowId,
    _In_ const uint32_t keyCredentialCacheOption,
    _Out_ std::vector<std::uint8_t>& securedEncryptionKeyBytes)
{
    try
    {
        debug_print(L"Start MyEnclaveCreateUserBoundKey");

        // VTL1 creates secure cache configuration - VTL0 input is ignored
        auto secureConfig = CreateSecureKeyCredentialCacheConfig();

        debug_print(L"Created secure cache configuration in VTL1");

        // Create a user-bound key with enclave sealing
        auto keyBytes = veil::vtl1::userboundkey::create_user_bound_key(
            helloKeyName,
            secureConfig,
            pinMessage,
            windowId,
            ENCLAVE_SEALING_IDENTITY_POLICY::ENCLAVE_IDENTITY_POLICY_SEAL_SAME_IMAGE,
            g_runtimePolicy,
            keyCredentialCacheOption);
        debug_print(L"create_user_bound_key returned");

        // Store the user-bound key bytes directly - do NOT try to create a symmetric key from them
        securedEncryptionKeyBytes.assign(keyBytes.begin(), keyBytes.end());
        
        // Do NOT try to create a symmetric key here - user-bound keys must be loaded properly
        // g_encryptionKey will be set in the load functions

        return S_OK;
    }
    CATCH_RETURN();
}

//
// Load user bound key and encrypt data
//
HRESULT VbsEnclave::Trusted::Implementation::MyEnclaveLoadUserBoundKeyAndEncryptData(
    _In_ const std::wstring& helloKeyName,
    _In_ const std::wstring& pinMessage,
    _In_ const uintptr_t windowId,
    _In_ const std::vector<std::uint8_t>& securedEncryptionKeyBytes,
    _In_ const std::wstring& inputData,
    _Out_ std::vector<std::uint8_t>& combinedOutputData,
    _Out_ bool& needsReseal,
    _Out_ std::vector<std::uint8_t>& resealedEncryptionKeyBytes)
{
    // Initialize output parameters
    needsReseal = false;
    resealedEncryptionKeyBytes.clear();

    try
    {
        debug_print(L"Start MyEnclaveLoadUserBoundKeyAndEncryptData");

        // Ensure the user-bound key is loaded (handles reseal if needed)
        RETURN_IF_FAILED(EnsureUserBoundKeyLoaded(
            helloKeyName,
            pinMessage,
            windowId,
            securedEncryptionKeyBytes,
            needsReseal,
            resealedEncryptionKeyBytes));

        // Use the global key for encryption
        debug_print(L"Encrypting input data");
        auto keyHandle = GetEncryptionKeyHandle();
        auto [encryptedText, encryptionTag] = veil::vtl1::crypto::encrypt(
            keyHandle, 
            veil::vtl1::as_data_span(inputData.c_str()), 
            veil::vtl1::crypto::zero_nonce);

        debug_print(L"Encryption completed, encrypted size: %d, tag size: %d", 
            encryptedText.size(), encryptionTag.size());

        // Combine tag and encrypted data into single output
        // Format: [tag_size (4 bytes)][tag_data][encrypted_data]
        uint32_t tagSize = static_cast<uint32_t>(encryptionTag.size());
        combinedOutputData.clear();
        combinedOutputData.reserve(sizeof(tagSize) + encryptionTag.size() + encryptedText.size());
  
        // Append tag size (4 bytes) at the beginning
        const uint8_t* tagSizeBytes = reinterpret_cast<const uint8_t*>(&tagSize);
        combinedOutputData.insert(combinedOutputData.end(), tagSizeBytes, tagSizeBytes + sizeof(tagSize));
  
        // Append tag data
        combinedOutputData.insert(combinedOutputData.end(), encryptionTag.begin(), encryptionTag.end());
 
        // Append encrypted data
        combinedOutputData.insert(combinedOutputData.end(), encryptedText.begin(), encryptedText.end());

        debug_print(L"Combined data created, total size: %u (tag_size: %u, tag: %u, encrypted: %u)", 
            static_cast<uint32_t>(combinedOutputData.size()), 
            static_cast<uint32_t>(sizeof(tagSize)),
            static_cast<uint32_t>(encryptionTag.size()), 
            static_cast<uint32_t>(encryptedText.size()));
    }
    CATCH_RETURN();

    return S_OK;
}

//
// Load user bound key and decrypt data
//
HRESULT VbsEnclave::Trusted::Implementation::MyEnclaveLoadUserBoundKeyAndDecryptData(
    _In_ const std::wstring& helloKeyName,
    _In_ const std::wstring& pinMessage,
    _In_ const uintptr_t windowId,
    _In_ const std::vector<std::uint8_t>& securedEncryptionKeyBytes,
    _In_ const std::vector<std::uint8_t>& combinedInputData,
    _Out_ std::wstring& decryptedData,
    _Out_ bool& needsReseal,
    _Out_ std::vector<std::uint8_t>& resealedEncryptionKeyBytes)
{
    // Initialize output parameters
    needsReseal = false;
    resealedEncryptionKeyBytes.clear();

    try
    {
        debug_print(L"Start MyEnclaveLoadUserBoundKeyAndDecryptData");

        // Extract tag from the combined input data
        // Format: [tag_size (4 bytes)][tag_data][encrypted_data]
        if (combinedInputData.size() < sizeof(uint32_t))
        {
            debug_print(L"ERROR: Combined input data too small, size: %u", static_cast<uint32_t>(combinedInputData.size()));
            return E_INVALIDARG;
        }

        // Read tag size from the first 4 bytes
        uint32_t tagSize;
        std::memcpy(&tagSize, combinedInputData.data(), sizeof(uint32_t));
 
        debug_print(L"Extracted tag size: %d", tagSize);

        // Validate tag size
        if (tagSize > combinedInputData.size() - sizeof(uint32_t) || tagSize == 0)
        {  
            debug_print(L"ERROR: Invalid tag size: %u, combined data size: %u", tagSize, static_cast<uint32_t>(combinedInputData.size()));
            return E_INVALIDARG;
        }

        auto it = combinedInputData.begin() + sizeof(uint32_t);

        // Extract tag data (after tag size)
        std::vector<uint8_t> tag(
            it,
            it + tagSize
        );
        it += tagSize;

        // Extract encrypted data (everything after tag size and tag data)
        std::vector<uint8_t> encryptedInputBytes(
            it,
            combinedInputData.end()
        );

        debug_print(L"Extracted tag size: %u, encrypted data size: %u", 
            static_cast<uint32_t>(tag.size()), 
            static_cast<uint32_t>(encryptedInputBytes.size()));

        // Ensure the user-bound key is loaded (handles reseal if needed)
        RETURN_IF_FAILED(EnsureUserBoundKeyLoaded(
            helloKeyName,
            pinMessage,
            windowId,
            securedEncryptionKeyBytes,
            needsReseal,
            resealedEncryptionKeyBytes));

        // Use the global key for decryption
        debug_print(L"Decrypting input data, encrypted size: %u, tag size: %u", 
            static_cast<uint32_t>(encryptedInputBytes.size()), 
            static_cast<uint32_t>(tag.size()));
  
        auto keyHandle = GetEncryptionKeyHandle();
        auto decryptedBytes = veil::vtl1::crypto::decrypt(
            keyHandle, 
            encryptedInputBytes, 
            veil::vtl1::crypto::zero_nonce, 
            tag);

        // Convert decrypted bytes to wstring
        decryptedData = veil::vtl1::to_wstring(decryptedBytes);
        
        debug_print(L"Decryption completed, decrypted string: %ws", decryptedData.c_str());
    }
    CATCH_RETURN();

    return S_OK;
}
