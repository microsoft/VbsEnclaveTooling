#include "pch.h"

#define VEIL_IMPLEMENTATION

#include <VbsEnclave\Enclave\Implementations.h>
#include "crypto.vtl1.h"
#include "utils.vtl1.h"
#include "vengcdll.h" // OS APIs
// #include <veinterop_kcm.h>
#include "userboundkey.any.h"
#include "userboundkey.vtl1.h" // Function declarations
#include "vtl0_functions.vtl1.h"
#include "object_table.vtl1.h"

namespace veil::vtl1::userboundkey
{

// Helper function to convert USER_BOUND_KEY_SESSION_HANDLE to DeveloperTypes::sessionInfo
USER_BOUND_KEY_SESSION_HANDLE ConvertToSessionHandle(uintptr_t sessionInfo)
{
    return reinterpret_cast<USER_BOUND_KEY_SESSION_HANDLE>(sessionInfo);
}

// Helper function to convert USER_BOUND_KEY_SESSION_HANDLE to DeveloperTypes::sessionInfo
uintptr_t ConvertFromSessionHandle(USER_BOUND_KEY_SESSION_HANDLE sessionHandle)
{
    return reinterpret_cast<uintptr_t>(sessionHandle);
}
}

namespace veil_abi::VTL1_Declarations
{

// RAII wrapper using WIL for heap-allocated memory to prevent resource leaks
namespace
{
    inline void heap_deleter(void* ptr) noexcept
    {
        if (ptr)
        {
            HeapFree(GetProcessHeap(), 0, ptr);
        }
    }
}

using unique_heap_ptr = wil::unique_any<
    void*,
    decltype(&heap_deleter),
    heap_deleter,
    wil::details::pointer_access_all,
    void*,
    decltype(nullptr),
    nullptr
>;

DeveloperTypes::attestationReportAndSessionInfo userboundkey_get_attestation_report(_In_ const std::vector<std::uint8_t>& challenge)
{
    USER_BOUND_KEY_SESSION_HANDLE sessionHandle = nullptr; // Declare session handle for proper cleanup

    // DEBUG: Log that the enclave function has been called
    veil::vtl1::vtl0_functions::debug_print(L"DEBUG: userboundkey_get_attestation_report called - enclave function started");
    
    // DEBUG: Add hex dump of the challenge buffer
    std::wstring challengeHex = L"DEBUG: Challenge buffer (size=" + std::to_wstring(challenge.size()) + L"): ";
    for (size_t i = 0; i < challenge.size() && i < 64; ++i) { // Limit to first 64 bytes to avoid excessive output
        wchar_t hexByte[4];
        swprintf_s(hexByte, L"%02X ", challenge[i]);
        challengeHex += hexByte;
    }
    if (challenge.size() > 64) {
        challengeHex += L"... (truncated)";
    }
    veil::vtl1::vtl0_functions::debug_print(challengeHex.c_str());
    
    unique_heap_ptr reportPtr; // RAII wrapper for automatic cleanup
    size_t reportSize = 0;

    // DEBUG: Log before calling InitializeUserBoundKeySessionInfo
    veil::vtl1::vtl0_functions::debug_print(L"DEBUG: About to call InitializeUserBoundKeySessionInfo");

    // Safe overflow check before casting
    if (challenge.size() > UINT32_MAX) {
        veil::vtl1::vtl0_functions::debug_print(L"ERROR: Challenge size exceeds UINT32_MAX");
        throw std::overflow_error("Challenge size exceeds UINT32_MAX");
    }

    THROW_IF_FAILED(InitializeUserBoundKeySessionInfo(
        challenge.data(),
        static_cast<UINT32>(challenge.size()),
        reportPtr.put(), // RAII wrapper handles cleanup automatically
        reinterpret_cast<UINT32*>(&reportSize),
        &sessionHandle)); // OS CALL

    // DEBUG: Log after InitializeUserBoundKeySessionInfo completes
    veil::vtl1::vtl0_functions::debug_print(L"DEBUG: InitializeUserBoundKeySessionInfo completed successfully");

    // Create vector from the allocated memory - RAII will handle cleanup
    uint8_t* rawPtr = static_cast<uint8_t*>(reportPtr.get());
    std::vector<uint8_t> report(rawPtr, rawPtr + reportSize);
    
    // Memory is automatically freed by unique_heap_ptr destructor

    // DEBUG: Log before returning
    veil::vtl1::vtl0_functions::debug_print(L"DEBUG: userboundkey_get_attestation_report returning successfully");

    auto sessionInfo = veil::vtl1::userboundkey::ConvertFromSessionHandle(sessionHandle);
    return DeveloperTypes::attestationReportAndSessionInfo {std::move(report), sessionInfo};
}
}

namespace veil::vtl1::implementation::userboundkey::callouts
{
    DeveloperTypes::credentialAndFormattedKeyNameAndSessionInfo userboundkey_establish_session_for_create_callback(
        _In_ const void* enclave, 
        _In_ const std::wstring& key_name, 
        _In_ const uintptr_t ecdh_protocol, 
        _In_ const std::wstring& message, 
        _In_ const uintptr_t window_id, 
        _In_ const DeveloperTypes::keyCredentialCacheConfig& cache_config,
        _In_ const uint64_t nonce)
    {
        return veil_abi::VTL0_Callbacks::userboundkey_establish_session_for_create_callback(
            reinterpret_cast<uintptr_t>(enclave),
            key_name,
            ecdh_protocol,
            message,
            window_id,
            cache_config,
            nonce);
    }

    DeveloperTypes::credentialAndFormattedKeyNameAndSessionInfo userboundkey_establish_session_for_load_callback(
        _In_ const void* enclave,
        _In_ const std::wstring& key_name,
        _In_ const std::wstring& message, 
        _In_ const uintptr_t window_id,
        _In_ const uint64_t nonce)
    {
        return veil_abi::VTL0_Callbacks::userboundkey_establish_session_for_load_callback(
            reinterpret_cast<uintptr_t>(enclave),
            key_name,
            message,
            window_id,
            nonce);
    }

    // New function to extract secret and authorization context from credential
    std::vector<std::uint8_t> userboundkey_get_authorization_context_from_credential_callback(
        _In_ const std::vector<std::uint8_t>& credential_vector,
        _In_ const std::vector<std::uint8_t>& public_key,
        _In_ const std::wstring& message,
        _In_ const uintptr_t window_id)
    {
        return veil_abi::VTL0_Callbacks::userboundkey_get_authorization_context_from_credential_callback(
            credential_vector,
            public_key,
            message,
            window_id);
    }

    std::vector<std::uint8_t> userboundkey_get_secret_from_credential_callback(
        _In_ const std::vector<std::uint8_t>& credential_vector,
        _In_ const std::vector<std::uint8_t>& public_key,
        _In_ const std::wstring& message,
        _In_ const uintptr_t window_id)
    {
        return veil_abi::VTL0_Callbacks::userboundkey_get_secret_from_credential_callback(
            credential_vector,
            public_key,
            message,
            window_id);
    }
}

namespace veil::vtl1::userboundkey
{
// RAII wrapper using WIL for USER_BOUND_KEY_AUTH_CONTEXT_HANDLE to prevent resource leaks
namespace
{
    inline void close_auth_context_handle(USER_BOUND_KEY_AUTH_CONTEXT_HANDLE handle) noexcept
    {
        if (handle)
        {
            // CloseUserBoundKeyAuthContextHandle returns HRESULT, but we're in a noexcept context
            // so we ignore the return value (similar to the original implementation)
            (void)CloseUserBoundKeyAuthContextHandle(handle);
        }
    }
}

using unique_auth_context_handle = wil::unique_any<
    USER_BOUND_KEY_AUTH_CONTEXT_HANDLE,
    decltype(&close_auth_context_handle),
    close_auth_context_handle,
    wil::details::pointer_access_all,
    USER_BOUND_KEY_AUTH_CONTEXT_HANDLE,
    decltype(nullptr),
    nullptr
>;

std::vector<uint8_t> GetEphemeralPublicKeyBytesFromBoundKeyBytes(wil::secure_vector<uint8_t> boundKeyBytes)
{
    // The bound key structure is created in CreateBoundKeyStructure() in veinterop.dll:
    // [enclave public key blob size (4 bytes)]
    // [enclave public key blob]  
    // [nonce (12 bytes)]
    // [encrypted user key size (4 bytes)]
    // [encrypted user key data]
    // [authentication tag (16 bytes)]

    // We need to extract the enclave public key blob (the "ephemeral public key")

    veil::vtl1::vtl0_functions::debug_print((L"DEBUG: GetEphemeralPublicKeyBytesFromBoundKeyBytes - Starting with boundKeyBytes.size(): " + std::to_wstring(boundKeyBytes.size())).c_str());

    if (boundKeyBytes.size() < sizeof(uint32_t))
    {
        veil::vtl1::vtl0_functions::debug_print(L"ERROR: GetEphemeralPublicKeyBytesFromBoundKeyBytes - Bound key bytes too small - missing size field");
        throw std::invalid_argument("Bound key bytes too small - missing size field");
    }

    const uint8_t* pCurrentPos = boundKeyBytes.data();

    // Read the enclave public key blob size (first 4 bytes)
    uint32_t enclavePublicKeyBlobSize = *reinterpret_cast<const uint32_t*>(pCurrentPos);
    pCurrentPos += sizeof(uint32_t);

    veil::vtl1::vtl0_functions::debug_print((L"DEBUG: GetEphemeralPublicKeyBytesFromBoundKeyBytes - enclavePublicKeyBlobSize: " + std::to_wstring(enclavePublicKeyBlobSize)).c_str());

    // Validate that we have enough data for the full public key blob
    size_t remainingBytes = boundKeyBytes.size() - sizeof(uint32_t);
    veil::vtl1::vtl0_functions::debug_print((L"DEBUG: GetEphemeralPublicKeyBytesFromBoundKeyBytes - remainingBytes: " + std::to_wstring(remainingBytes)).c_str());

    if (remainingBytes < enclavePublicKeyBlobSize)
    {
        veil::vtl1::vtl0_functions::debug_print((L"ERROR: GetEphemeralPublicKeyBytesFromBoundKeyBytes - Insufficient data for public key blob. Need: " + std::to_wstring(enclavePublicKeyBlobSize) + L", Have: " + std::to_wstring(remainingBytes)).c_str());
        throw std::runtime_error("Bound key bytes corrupted - insufficient data for public key blob");
    }

    // Additional validation: check for unreasonably large public key size
    if (enclavePublicKeyBlobSize > remainingBytes || enclavePublicKeyBlobSize == 0)
    {
        veil::vtl1::vtl0_functions::debug_print((L"ERROR: GetEphemeralPublicKeyBytesFromBoundKeyBytes - Invalid public key blob size: " + std::to_wstring(enclavePublicKeyBlobSize) + L" (remainingBytes: " + std::to_wstring(remainingBytes) + L")").c_str());

        // Add hex dump of first 16 bytes for debugging
        std::wstring hexDump = L"First 16 bytes of boundKeyBytes: ";
        size_t maxBytes = boundKeyBytes.size() < 16 ? boundKeyBytes.size() : 16;
        for (size_t i = 0; i < maxBytes; ++i)
        {
            wchar_t hexByte[4];
            swprintf_s(hexByte, L"%02X ", boundKeyBytes[i]);
            hexDump += hexByte;
        }
        veil::vtl1::vtl0_functions::debug_print(hexDump.c_str());

        throw std::runtime_error("Bound key bytes corrupted - invalid public key blob size");
    }

    // Extract the enclave public key blob
    std::vector<uint8_t> ephemeralPublicKey(pCurrentPos, pCurrentPos + enclavePublicKeyBlobSize);

    veil::vtl1::vtl0_functions::debug_print((L"DEBUG: GetEphemeralPublicKeyBytesFromBoundKeyBytes - Successfully extracted ephemeral public key, size: " + std::to_wstring(ephemeralPublicKey.size())).c_str());

    return ephemeralPublicKey;
}

wil::secure_vector<uint8_t> enclave_create_user_bound_key(
    const std::wstring& keyName,
    DeveloperTypes::keyCredentialCacheConfig& cacheConfig,
    const std::wstring& message,
    uintptr_t windowId,
    ENCLAVE_SEALING_IDENTITY_POLICY sealingPolicy)
{
    veil::vtl1::vtl0_functions::debug_print(L"DEBUG: enclave_create_user_bound_key - Function entered");

    try
    {
        // Convert cacheConfig to the type expected by the callback
        auto devCacheConfig = cacheConfig;
        void* encryptedKcmRequestRac = nullptr;
        UINT32 encryptedKcmRequestRacSize = 0;
        ULONG64 localNonce = 0; // captures the nonce used in the encrypted request, will be used in the corresponding decrypt call

        // SESSION
        void* enclave = veil::vtl1::enclave_information().BaseAddress;
        auto credentialAndFormattedKeyNameAndSessionInfoResult = veil_abi::VTL0_Callbacks::userboundkey_establish_session_for_create_callback(
            reinterpret_cast<uint64_t>(enclave),
            keyName,
            reinterpret_cast<uintptr_t>(BCRYPT_ECDH_P384_ALG_HANDLE),
            message,
            windowId,
            devCacheConfig,
            0 /* sessionNonce */);

        veil::vtl1::vtl0_functions::debug_print(L"DEBUG: enclave_create_user_bound_key - Received credentialAndFormattedKeyNameAndSessionInfo");

        // Extract credential vector and session info from first call
        auto& credentialVector = credentialAndFormattedKeyNameAndSessionInfoResult.credential;
        auto sessionHandle = ConvertToSessionHandle(credentialAndFormattedKeyNameAndSessionInfoResult.sessionInfo);
        auto& formattedKeyName = credentialAndFormattedKeyNameAndSessionInfoResult.formattedKeyName;

        veil::vtl1::vtl0_functions::debug_print((L"DEBUG: enclave_create_user_bound_key - credentialVector size: " + std::to_wstring(credentialVector.size())).c_str());

        const void* keyNamePtr = formattedKeyName.c_str();
        UINT32 keyNameSizeBytes = static_cast<UINT32>(formattedKeyName.length() * sizeof(wchar_t)); // Exclude null terminator

        // DEBUG: Print formattedKeyName and keyNameSizeBytes
        veil::vtl1::vtl0_functions::debug_print((L"DEBUG: enclave_create_user_bound_key - formattedKeyName: " + formattedKeyName).c_str());
        veil::vtl1::vtl0_functions::debug_print((L"DEBUG: enclave_create_user_bound_key - keyNameSizeBytes (without null terminator): " + std::to_wstring(keyNameSizeBytes)).c_str());

        // Call to veinterop to create the encrypted KCM request for RetrieveAuthorizationContext
        // Use the function that accepts session handle and handles nonce manipulation internally
        THROW_IF_FAILED(CreateEncryptedRequestForRetrieveAuthorizationContext(
            sessionHandle,  // Pass session handle - nonce manipulation is handled internally
            keyNamePtr,
            keyNameSizeBytes,
            &localNonce,
            &encryptedKcmRequestRac,
            &encryptedKcmRequestRacSize)); // OS CALL

        // Convert the result to vector for the callback
        std::vector<uint8_t> encryptedKcmRequestForRetrieveAuthorizationContext;
        THROW_IF_FAILED(encryptedKcmRequestRac == nullptr || encryptedKcmRequestRacSize <= 0 ? E_INVALIDARG : S_OK);
        encryptedKcmRequestForRetrieveAuthorizationContext.assign(
            static_cast<uint8_t*>(encryptedKcmRequestRac),
            static_cast<uint8_t*>(encryptedKcmRequestRac) + encryptedKcmRequestRacSize);

        // Free the allocated memory
        HeapFree(GetProcessHeap(), 0, encryptedKcmRequestRac);

        // Second call to extract secret from credential
        veil::vtl1::vtl0_functions::debug_print(L"DEBUG: enclave_create_user_bound_key - About to call userboundkey_get_authorization_context_from_credential_callback");

        auto authContextBlob = veil_abi::VTL0_Callbacks::userboundkey_get_authorization_context_from_credential_callback(
            credentialVector,
            encryptedKcmRequestForRetrieveAuthorizationContext,
            message,
            windowId);

        veil::vtl1::vtl0_functions::debug_print(L"DEBUG: enclave_create_user_bound_key - userboundkey_get_authorization_context_from_credential_callback completed");

        // AUTH CONTEXT
        unique_auth_context_handle authContext;
        THROW_IF_FAILED(GetUserBoundKeyAuthContext(
            sessionHandle,
            authContextBlob.data(),
            static_cast<UINT32>(authContextBlob.size()),
            localNonce,
            authContext.put()
        )); // OS CALL
        
        veil::vtl1::vtl0_functions::debug_print(L"DEBUG: enclave_create_user_bound_key - GetUserBoundKeyAuthContext completed");

        // Validate
        USER_BOUND_KEY_AUTH_CONTEXT_PROPERTY propCacheConfig;
        propCacheConfig.name = UserBoundKeyAuthContextPropertyCacheConfig;
        propCacheConfig.size = sizeof(cacheConfig);
        propCacheConfig.value = &cacheConfig;

        THROW_IF_FAILED(ValidateUserBoundKeyAuthContext(
            formattedKeyName.c_str(),
            authContext.get(),
            1,
            &propCacheConfig)); // OS CALL
        veil::vtl1::vtl0_functions::debug_print(L"DEBUG: enclave_create_user_bound_key - ValidateUserBoundKeyAuthContext completed");

        // USERKEY
        auto userkeyBytes = veil::vtl1::crypto::generate_symmetric_key_bytes();
        veil::vtl1::vtl0_functions::debug_print(L"DEBUG: enclave_create_user_bound_key - Generated user key bytes");

        // ENCRYPT USERKEY - CORRECTED VERSION  
        void* pBoundKey = nullptr;
        UINT32 cbBoundKeyBytes = 0;
        veil::vtl1::vtl0_functions::debug_print(L"DEBUG: enclave_create_user_bound_key - About to call ProtectUserBoundKey");
        THROW_IF_FAILED(ProtectUserBoundKey(
            authContext.get(),
            userkeyBytes.data(),
            static_cast<UINT32>(userkeyBytes.size()),
            &pBoundKey,        // CORRECT: address of pointer for dynamic allocation
            &cbBoundKeyBytes   // Will be set to actual size by ProtectUserBoundKey
        )); // OS CALL
        veil::vtl1::vtl0_functions::debug_print((L"DEBUG: enclave_create_user_bound_key - ProtectUserBoundKey returned boundKey size: " + std::to_wstring(cbBoundKeyBytes)).c_str());

        // Convert dynamically allocated buffer to vector for sealing
        std::vector<uint8_t> boundKeyBytes(
            static_cast<uint8_t*>(pBoundKey),
            static_cast<uint8_t*>(pBoundKey) + cbBoundKeyBytes
        );

        // Free the dynamically allocated memory
        HeapFree(GetProcessHeap(), 0, pBoundKey);

        // Memory is automatically freed by unique_heap_ptr destructor;

        // Clean up session info before sealing
        CloseUserBoundKeySession(sessionHandle);

        // SEAL
        auto sealedKeyMaterial = veil::vtl1::crypto::seal_data(boundKeyBytes, sealingPolicy, ENCLAVE_RUNTIME_POLICY_ALLOW_FULL_DEBUG);
        veil::vtl1::vtl0_functions::debug_print(L"DEBUG: enclave_create_user_bound_key - Function completed successfully");
        return sealedKeyMaterial;
    }
    catch (const std::exception& e)
    {
        // Clean up session info on exception
        //CloseUserBoundKeySession(sessionHandle);

        // Convert exception message to wide string for debug printing
        std::string error_msg = e.what();
        std::wstring werror_msg(error_msg.begin(), error_msg.end());
        veil::vtl1::vtl0_functions::debug_print((L"ERROR: enclave_create_user_bound_key - Exception caught: " + werror_msg).c_str());
        throw; // Re-throw the exception
    }
    catch (...)
    {
        // Clean up session info on exception
        //CloseUserBoundKeySession(sessionHandle);

        veil::vtl1::vtl0_functions::debug_print(L"ERROR: enclave_create_user_bound_key - Unknown exception caught");
        throw; // Re-throw the exception
    }
}

std::vector<uint8_t> enclave_load_user_bound_key(
    const std::wstring& keyName,
    DeveloperTypes::keyCredentialCacheConfig& cacheConfig,
    const std::wstring& message,
    uintptr_t windowId,
    std::vector<uint8_t>& sealedBoundKeyBytes)
{
    veil::vtl1::vtl0_functions::debug_print(L"DEBUG: enclave_load_user_bound_key - Function entered");
    USER_BOUND_KEY_SESSION_HANDLE sessionHandle = nullptr; // Declare session handle for proper cleanup

    try
    {
        ULONG64 localNonce = 0; // captures the nonce used in the encrypted request, will be used in the corresponding decrypt call

        // UNSEAL
        veil::vtl1::vtl0_functions::debug_print(L"DEBUG: enclave_load_user_bound_key - About to call unseal_data");
        veil::vtl1::vtl0_functions::debug_print((L"DEBUG: enclave_load_user_bound_key - sealedBoundKeyBytes size: " + std::to_wstring(sealedBoundKeyBytes.size())).c_str());

        auto boundKeyBytesMaterial = veil::vtl1::crypto::unseal_data(sealedBoundKeyBytes);

        veil::vtl1::vtl0_functions::debug_print(L"DEBUG: enclave_load_user_bound_key - unseal_data completed successfully");

        auto& boundKeyBytes = boundKeyBytesMaterial.first;
        veil::vtl1::vtl0_functions::debug_print((L"DEBUG: enclave_load_user_bound_key - boundKeyBytes size: " + std::to_wstring(boundKeyBytes.size())).c_str());

        std::vector<uint8_t> ephemeralPublicKeyBytes = GetEphemeralPublicKeyBytesFromBoundKeyBytes(boundKeyBytes);
        veil::vtl1::vtl0_functions::debug_print((L"DEBUG: enclave_load_user_bound_key - ephemeralPublicKeyBytes size: " + std::to_wstring(ephemeralPublicKeyBytes.size())).c_str());

        // SESSION - First call to get credential and sessionInfo
        veil::vtl1::vtl0_functions::debug_print(L"DEBUG: enclave_load_user_bound_key - About to call establish_session_for_load_callback");

        void* enclave = veil::vtl1::enclave_information().BaseAddress;
        auto credentialAndFormattedKeyNameAndSessionInfoResult = veil::vtl1::implementation::userboundkey::callouts::userboundkey_establish_session_for_load_callback(
            enclave,
            keyName,
            message,
            windowId,
            0 /* sessionNonce */);

        veil::vtl1::vtl0_functions::debug_print(L"DEBUG: enclave_load_user_bound_key - establish_session_for_load_callback completed");

        // Extract credential vector and session info from first call
        auto& credentialVector = credentialAndFormattedKeyNameAndSessionInfoResult.credential;
        auto sessionHandle = ConvertToSessionHandle(credentialAndFormattedKeyNameAndSessionInfoResult.sessionInfo);
        auto& formattedKeyName = credentialAndFormattedKeyNameAndSessionInfoResult.formattedKeyName;

        veil::vtl1::vtl0_functions::debug_print((L"DEBUG: enclave_load_user_bound_key - credentialVector size: " + std::to_wstring(credentialVector.size())).c_str());

        // Call to veinterop to create the encrypted KCM request for RetrieveAuthorizationContext
        void* encryptedKcmRequestRac = nullptr;
        UINT32 encryptedKcmRequestRacSize = 0;

        // Call to veinterop to create the encrypted KCM request for DeriveSharedSecret
        void* encryptedKcmRequestDss = nullptr;
        UINT32 encryptedKcmRequestDssSize = 0;

        const void* keyNamePtr = formattedKeyName.c_str();
        UINT32 keyNameSizeBytes = static_cast<UINT32>(formattedKeyName.length() * sizeof(wchar_t)); // Exclude null terminator

        // DEBUG: Print formattedKeyName and keyNameSizeBytes
        veil::vtl1::vtl0_functions::debug_print((L"DEBUG: enclave_load_user_bound_key - formattedKeyName: " + formattedKeyName).c_str());
        veil::vtl1::vtl0_functions::debug_print((L"DEBUG: enclave_load_user_bound_key - keyNameSizeBytes (without null terminator): " + std::to_wstring(keyNameSizeBytes)).c_str());

        // Use the function that accepts session handle and handles nonce manipulation internally
        THROW_IF_FAILED(CreateEncryptedRequestForRetrieveAuthorizationContext(
            sessionHandle,  // Pass session handle - nonce manipulation is handled internally
            keyNamePtr,
            keyNameSizeBytes,
            &localNonce,
            &encryptedKcmRequestRac,
            &encryptedKcmRequestRacSize)); // OS CALL

        // Convert the result to vector for the callback
        std::vector<uint8_t> encryptedKcmRequestForRetrieveAuthorizationContext;
        THROW_IF_FAILED(encryptedKcmRequestRac == nullptr || encryptedKcmRequestRacSize <= 0 ? E_INVALIDARG : S_OK);
        encryptedKcmRequestForRetrieveAuthorizationContext.assign(
            static_cast<uint8_t*>(encryptedKcmRequestRac),
            static_cast<uint8_t*>(encryptedKcmRequestRac) + encryptedKcmRequestRacSize);

        // Free the allocated memory
        HeapFree(GetProcessHeap(), 0, encryptedKcmRequestRac);

        // Second call to extract secret from credential
        veil::vtl1::vtl0_functions::debug_print(L"DEBUG: enclave_load_user_bound_key - About to call userboundkey_get_authorization_context_from_credential_callback");

        auto authContextBlob = veil_abi::VTL0_Callbacks::userboundkey_get_authorization_context_from_credential_callback(
            credentialVector,
            encryptedKcmRequestForRetrieveAuthorizationContext,
            message,
            windowId);

        veil::vtl1::vtl0_functions::debug_print(L"DEBUG: enclave_load_user_bound_key - userboundkey_get_authorization_context_from_credential_callback completed");
        veil::vtl1::vtl0_functions::debug_print((L"DEBUG: enclave_load_user_bound_key - authContextBlob size: " + std::to_wstring(authContextBlob.size())).c_str());

        // AUTH CONTEXT
        veil::vtl1::vtl0_functions::debug_print(L"DEBUG: enclave_load_user_bound_key - About to call GetUserBoundKeyAuthContext");
        unique_auth_context_handle authContext;
        THROW_IF_FAILED(GetUserBoundKeyAuthContext(
            sessionHandle,
            authContextBlob.data(),
            static_cast<UINT32>(authContextBlob.size()),
            localNonce,
            authContext.put())); // OS CALL
        veil::vtl1::vtl0_functions::debug_print(L"DEBUG: enclave_load_user_bound_key - GetUserBoundKeyAuthContext completed");

        // Validate
        veil::vtl1::vtl0_functions::debug_print(L"DEBUG: enclave_load_user_bound_key - About to validate auth context");
        USER_BOUND_KEY_AUTH_CONTEXT_PROPERTY propCacheConfig;
        propCacheConfig.name = UserBoundKeyAuthContextPropertyCacheConfig;
        propCacheConfig.size = sizeof(cacheConfig);
        propCacheConfig.value = &cacheConfig;
        THROW_IF_FAILED(ValidateUserBoundKeyAuthContext(
            formattedKeyName.c_str(),
            authContext.get(),
            1,
            &propCacheConfig)); // OS CALL
        veil::vtl1::vtl0_functions::debug_print(L"DEBUG: enclave_load_user_bound_key - Auth context validation completed");

        // Use the function that accepts session handle and handles nonce manipulation internally
        THROW_IF_FAILED(CreateEncryptedRequestForDeriveSharedSecret(
            sessionHandle,  // Pass session handle - nonce manipulation is handled internally
            keyNamePtr,
            keyNameSizeBytes,
            ephemeralPublicKeyBytes.data(),
            static_cast<UINT32>(ephemeralPublicKeyBytes.size()),
            &localNonce,
            &encryptedKcmRequestDss,
            &encryptedKcmRequestDssSize)); // OS CALL

        // Convert the result to vector for the callback
        std::vector<uint8_t> encryptedKcmRequestForDeriveSharedSecret;
        THROW_IF_FAILED(encryptedKcmRequestDss == nullptr || encryptedKcmRequestDssSize <= 0 ? E_INVALIDARG : S_OK);
        encryptedKcmRequestForDeriveSharedSecret.assign(
            static_cast<uint8_t*>(encryptedKcmRequestDss),
            static_cast<uint8_t*>(encryptedKcmRequestDss) + encryptedKcmRequestDssSize);

        // Free the allocated memory
        HeapFree(GetProcessHeap(), 0, encryptedKcmRequestDss);

        // Second call to extract secret from credential
        veil::vtl1::vtl0_functions::debug_print(L"DEBUG: enclave_load_user_bound_key - About to call userboundkey_get_secret_from_credential_callback");

        auto secret = veil_abi::VTL0_Callbacks::userboundkey_get_secret_from_credential_callback(
            credentialVector,
            encryptedKcmRequestForDeriveSharedSecret,
            message,
            windowId);

        veil::vtl1::vtl0_functions::debug_print(L"DEBUG: enclave_load_user_bound_key - userboundkey_get_secret_from_credential_callback completed");
        veil::vtl1::vtl0_functions::debug_print((L"DEBUG: enclave_load_user_bound_key - secret size: " + std::to_wstring(secret.size())).c_str());

        // DECRYPT USERKEY
        veil::vtl1::vtl0_functions::debug_print(L"DEBUG: enclave_load_user_bound_key - About to call UnprotectUserBoundKey");
        UINT32 cbUserkeyBytes = 0;
        void* pUserkeyBytes = nullptr;

        // Use the existing session handle for the API call
        THROW_IF_FAILED(UnprotectUserBoundKey(
            sessionHandle,
            authContext.get(),
            secret.data(),
            static_cast<UINT32>(secret.size()),
            boundKeyBytes.data(),
            static_cast<UINT32>(boundKeyBytes.size()),
            localNonce,
            &pUserkeyBytes,
            &cbUserkeyBytes)); // OS CALL
        veil::vtl1::vtl0_functions::debug_print(L"DEBUG: enclave_load_user_bound_key - UnprotectUserBoundKey completed");

        std::vector<uint8_t> userkeyBytes(static_cast<uint8_t*>(pUserkeyBytes), static_cast<uint8_t*>(pUserkeyBytes) + cbUserkeyBytes);
        HeapFree(GetProcessHeap(), 0, pUserkeyBytes);

        // Clean up session handle before returning
        CloseUserBoundKeySession(sessionHandle);

        veil::vtl1::vtl0_functions::debug_print(L"DEBUG: enclave_load_user_bound_key - Function completed successfully");
        return userkeyBytes;
    }
    catch (const std::exception& e)
    {
        // Clean up session key on exception
        CloseUserBoundKeySession(sessionHandle);

        // Convert exception message to wide string for debug printing
        std::string error_msg = e.what();
        std::wstring werror_msg(error_msg.begin(), error_msg.end());
        veil::vtl1::vtl0_functions::debug_print((L"ERROR: enclave_load_user_bound_key - Exception caught: " + werror_msg).c_str());
        throw; // Re-throw the exception
    }
    catch (...)
    {
        // Clean up session key on exception
        CloseUserBoundKeySession(sessionHandle);

        veil::vtl1::vtl0_functions::debug_print(L"ERROR: enclave_load_user_bound_key - Unknown exception caught");
        throw; // Re-throw the exception
    }
}
} // namespace veil::vtl1::userboundkey
