// Copyright (c) Microsoft Corporation.
//

#include <pch.h>
#include "userbound_signature.h"
#include "..\Common\globals.h"

#include <veil\enclave\crypto.vtl1.h>
#include <veil\enclave\vtl0_functions.vtl1.h>
#include <VbsEnclave\Enclave\Implementation\Types.h>

using namespace veil::vtl1::vtl0_functions;

// VTL1 function to create secure cache configuration for signature keys
veil::vtl1::userboundkey::keyCredentialCacheConfig CreateSecureKeyCredentialCacheConfigForSignature()
{
    veil::vtl1::userboundkey::keyCredentialCacheConfig secureConfig;
    
    // VTL1 sets secure cache configuration values
    // VTL0 cannot influence these security-critical settings
    secureConfig.cacheOption = 0; // NoCache - most secure option
    secureConfig.cacheTimeoutInSeconds = 0;
    secureConfig.cacheUsageCount = 0;
    
    return secureConfig;
}

// Helper function to ensure user-bound private key is loaded
HRESULT EnsureUserBoundPrivateKeyLoaded(
    _In_ const std::wstring& helloKeyName,
    _In_ const std::wstring& pinMessage,
    _In_ const uintptr_t windowId,
    _In_ const std::vector<std::uint8_t>& securedPrivateKeyBytes,
    _Inout_ bool& needsReseal,
    _Out_ std::vector<std::uint8_t>& resealedPrivateKeyBytes)
{
    // Only load the user-bound key if it's not already loaded
    if (!IsSignatureKeyLoaded())
    {
        debug_print(L"Signature key not loaded, loading user-bound private key");

        // VTL1 creates secure cache configuration
        auto secureConfig = CreateSecureKeyCredentialCacheConfigForSignature();

        debug_print(L"Created secure cache configuration in VTL1 for signature key");

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
                securedPrivateKeyBytes,
                needsReseal);
            loadSucceeded = true;
            debug_print(L"Successfully loaded user-bound private key on first attempt");
        }
        catch (...)
        {
            debug_print(L"First load attempt failed, checking if reseal is needed");
            loadSucceeded = false;
        }

        // If load failed and reseal is needed, attempt reseal and retry
        if (!loadSucceeded && needsReseal)
        {
            debug_print(L"Attempting to reseal user-bound private key");
      
            try
            {
                auto resealedBytes = veil::vtl1::userboundkey::reseal_user_bound_key(
                    securedPrivateKeyBytes,
                    ENCLAVE_SEALING_IDENTITY_POLICY::ENCLAVE_IDENTITY_POLICY_SEAL_SAME_IMAGE,
                    g_runtimePolicy);

                debug_print(L"Reseal completed, attempting to load with resealed key");

                // Store resealed bytes in output parameter
                resealedPrivateKeyBytes.assign(resealedBytes.begin(), resealedBytes.end());

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
                debug_print(L"Successfully loaded user-bound private key after reseal");
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
            throw;
        }

        // Import the private key for ECDSA signing
        auto privateKey = veil::vtl1::crypto::bcrypt_import_private_key(
            BCRYPT_ECDSA_P384_ALG_HANDLE,
            BCRYPT_ECCPRIVATE_BLOB,
            loadedKeyBytes);
        
        SetSignatureKey(std::move(privateKey));
        debug_print(L"Imported ECDSA private key from loaded user-bound key material");
    }
    else
    {
        debug_print(L"Signature key already loaded, using cached key");
    }

    return S_OK;
}

//
// Create user-bound asymmetric key pair for signing/verification
//
HRESULT VbsEnclave::Trusted::Implementation::MyEnclaveCreateUserBoundAsymmetricKey(
    _In_ const std::wstring& helloKeyName,
    _In_ const std::wstring& pinMessage,
    _In_ const uintptr_t windowId,
    _In_ const uint32_t keyCredentialCreationOption,
    _Out_ std::vector<std::uint8_t>& securedPrivateKeyBytes,
    _Out_ std::vector<std::uint8_t>& publicKeyBytes)
{
    try
    {
        debug_print(L"Start MyEnclaveCreateUserBoundAsymmetricKey");

        // Generate ECDSA P-384 key pair
        auto keyPair = veil::vtl1::crypto::generate_ecdsa_key_pair(
            BCRYPT_ECDSA_P384_ALG_HANDLE,
            veil::vtl1::crypto::SIGNATURE_KEY_SIZE_BITS);
        
        debug_print(L"Generated ECDSA P-384 key pair");

        // Export the private key
        auto privateKeyBytesUnsealed = veil::vtl1::crypto::bcrypt_export_private_key(
            keyPair.get(),
            BCRYPT_ECCPRIVATE_BLOB);
        
        debug_print(L"Exported private key, size: %u bytes", static_cast<uint32_t>(privateKeyBytesUnsealed.size()));

        // Export the public key
        publicKeyBytes = veil::vtl1::crypto::bcrypt_export_public_key(keyPair.get());
        
        debug_print(L"Exported public key, size: %u bytes", static_cast<uint32_t>(publicKeyBytes.size()));

        // VTL1 creates secure cache configuration
        auto secureConfig = CreateSecureKeyCredentialCacheConfigForSignature();

        debug_print(L"Created secure cache configuration in VTL1");

        // Create a user-bound key with the custom private key bytes and enclave sealing
        auto sealedKeyBytes = veil::vtl1::userboundkey::create_user_bound_key(
            helloKeyName,
            secureConfig,
            pinMessage,
            windowId,
            ENCLAVE_SEALING_IDENTITY_POLICY::ENCLAVE_IDENTITY_POLICY_SEAL_SAME_IMAGE,
            g_runtimePolicy,
            keyCredentialCreationOption,
            privateKeyBytesUnsealed);
        
        debug_print(L"create_user_bound_key returned, sealed size: %u bytes", static_cast<uint32_t>(sealedKeyBytes.size()));

        // Store the sealed private key bytes
        securedPrivateKeyBytes.assign(sealedKeyBytes.begin(), sealedKeyBytes.end());

        return S_OK;
    }
    CATCH_RETURN();
}

//
// Load user-bound private key and sign data
//
HRESULT VbsEnclave::Trusted::Implementation::MyEnclaveLoadUserBoundKeyAndSign(
    _In_ const std::wstring& helloKeyName,
    _In_ const std::wstring& pinMessage,
    _In_ const uintptr_t windowId,
    _In_ const std::vector<std::uint8_t>& securedPrivateKeyBytes,
    _In_ const std::wstring& inputData,
    _Out_ std::vector<std::uint8_t>& signatureData,
    _Out_ bool& needsReseal,
    _Out_ std::vector<std::uint8_t>& resealedPrivateKeyBytes)
{
    // Initialize output parameters
    needsReseal = false;
    resealedPrivateKeyBytes.clear();

    try
    {
        debug_print(L"Start MyEnclaveLoadUserBoundKeyAndSign");

        // Ensure the user-bound private key is loaded (handles reseal if needed)
        RETURN_IF_FAILED(EnsureUserBoundPrivateKeyLoaded(
            helloKeyName,
            pinMessage,
            windowId,
            securedPrivateKeyBytes,
            needsReseal,
            resealedPrivateKeyBytes));

        // Use the global private key for signing
        debug_print(L"Signing input data");
        auto keyHandle = GetSignatureKeyHandle();
        
        // Sign the data using ECDSA with SHA-384
        signatureData = veil::vtl1::crypto::ecdsa_sign(
            keyHandle,
            BCRYPT_SHA384_ALG_HANDLE,
            veil::vtl1::as_data_span(inputData.c_str()));

        debug_print(L"Signing completed, signature size: %u bytes", static_cast<uint32_t>(signatureData.size()));
    }
    CATCH_RETURN();

    return S_OK;
}

//
// Verify signature using public key (no Windows Hello prompt)
//
HRESULT VbsEnclave::Trusted::Implementation::MyEnclaveVerifySignature(
    _In_ const std::vector<std::uint8_t>& publicKeyBytes,
    _In_ const std::wstring& inputData,
    _In_ const std::vector<std::uint8_t>& signatureData,
    _Out_ bool& isValid)
{
    isValid = false;

    try
    {
        debug_print(L"Start MyEnclaveVerifySignature");
        debug_print(L"Public key size: %u bytes, signature size: %u bytes",
            static_cast<uint32_t>(publicKeyBytes.size()),
            static_cast<uint32_t>(signatureData.size()));

        // Import the public key for verification
        auto publicKey = veil::vtl1::crypto::bcrypt_import_public_key_for_signature(
            BCRYPT_ECDSA_P384_ALG_HANDLE,
            BCRYPT_ECCPUBLIC_BLOB,
            publicKeyBytes);
        
        debug_print(L"Imported public key for signature verification");

        // Verify the signature
        isValid = veil::vtl1::crypto::ecdsa_verify(
            publicKey.get(),
            veil::vtl1::as_data_span(inputData.c_str()),
            signatureData);

        debug_print(L"Verification completed, result: %s", isValid ? L"VALID" : L"INVALID");
    }
    CATCH_RETURN();

    return S_OK;
}
