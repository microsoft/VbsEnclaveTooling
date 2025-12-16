#include "pch.h"

#define VEIL_IMPLEMENTATION

#include "crypto.vtl1.h"
#include "utils.vtl1.h"
#include "userboundkey.any.h"
#include "userboundkey.vtl1.h" // Function declarations
#include "vtl0_functions.vtl1.h"
#include "object_table.vtl1.h"
#include <VbsEnclave\Enclave\Implementation\Trusted.h>
#include <VbsEnclave\Enclave\Stubs\Untrusted.h>

namespace veil::vtl1::userboundkey
{
using unique_sessionhandle = wil::unique_any<USER_BOUND_KEY_SESSION_HANDLE, decltype(&::CloseUserBoundKeySession), ::CloseUserBoundKeySession>;

// RAII wrapper for credentials using WIL
using unique_credential = wil::unique_any<uintptr_t, decltype(&veil_abi::Untrusted::Stubs::userboundkey_delete_credential), veil_abi::Untrusted::Stubs::userboundkey_delete_credential>;

// Helper function to convert session handle from uintptr_t
unique_sessionhandle ConvertToSessionHandle(uintptr_t sessionInfo)
{
    return unique_sessionhandle{reinterpret_cast<USER_BOUND_KEY_SESSION_HANDLE>(sessionInfo)};
}

// Helper function to convert session handle to uintptr_t
uintptr_t ConvertFromSessionHandle(unique_sessionhandle sessionHandle)
{
    return reinterpret_cast<uintptr_t>(sessionHandle.release());
}

// Helper function to convert keyCredentialCacheConfig to veil_abi::Types::keyCredentialCacheConfig
veil_abi::Types::keyCredentialCacheConfig ConvertCacheConfig(const veil::vtl1::userboundkey::keyCredentialCacheConfig& cache_config)
{
    veil_abi::Types::keyCredentialCacheConfig abi_cache_config;
    abi_cache_config.cacheOption = cache_config.cacheOption;
    abi_cache_config.cacheTimeoutInSeconds = cache_config.cacheTimeoutInSeconds;
    abi_cache_config.cacheUsageCount = cache_config.cacheUsageCount;
    return abi_cache_config;
}

// Helper function for creating hex dump strings
std::wstring CreateHexDump(const std::vector<uint8_t>& data, const std::wstring& prefix = L"", size_t maxBytes = 64)
{
    std::wstring hexDump = prefix;
    if (!prefix.empty()) 
    {
        hexDump += L" (size=" + std::to_wstring(data.size()) + L"): ";
    }
    
    size_t bytesToShow = data.size() < maxBytes ? data.size() : maxBytes;
    for (size_t i = 0; i < bytesToShow; ++i) 
    {
        wchar_t hexByte[4];
        swprintf_s(hexByte, L"%02X ", data[i]);
        hexDump += hexByte;
    }
    
    if (data.size() > maxBytes) {
        hexDump += L"... (truncated)";
    }
    
    return hexDump;
}
}

namespace veil_abi::Trusted::Implementation
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

veil_abi::Types::attestationReportAndSessionInfo userboundkey_get_attestation_report(_In_ const std::vector<std::uint8_t>& challenge)
{

    // DEBUG: Log that the enclave function has been called
    veil::vtl1::vtl0_functions::internal::debug_print(L"DEBUG: userboundkey_get_attestation_report called - enclave function started");
    
    // DEBUG: Add hex dump of the challenge buffer
    auto challengeHex = veil::vtl1::userboundkey::CreateHexDump(challenge, L"DEBUG: Challenge buffer");
    veil::vtl1::vtl0_functions::internal::debug_print(challengeHex.c_str());
    
    wil::unique_process_heap_ptr<void> reportPtr; // RAII wrapper for automatic cleanup
    size_t reportSize = 0;

    // DEBUG: Log before calling InitializeUserBoundKeySession
    veil::vtl1::vtl0_functions::internal::debug_print(L"DEBUG: About to call InitializeUserBoundKeySession");

    // Safe overflow check before casting
    if (challenge.size() > std::numeric_limits<uint32_t>::max()) 
    {
        veil::vtl1::vtl0_functions::internal::debug_print(L"ERROR: Challenge size exceeds std::numeric_limits<uint32_t>::max()");
        throw std::overflow_error("Challenge size exceeds std::numeric_limits<uint32_t>::max()");
    }

    veil::vtl1::userboundkey::unique_sessionhandle sessionHandle; // RAII wrapper for automatic cleanup
    THROW_IF_FAILED(InitializeUserBoundKeySession(
        challenge.data(),
        static_cast<uint32_t>(challenge.size()),
        wil::out_param(reportPtr), // RAII wrapper handles cleanup automatically
        reinterpret_cast<uint32_t*>(&reportSize),
        &sessionHandle)); // OS CALL

    // DEBUG: Log after InitializeUserBoundKeySession completes
    veil::vtl1::vtl0_functions::internal::debug_print(L"DEBUG: InitializeUserBoundKeySession completed successfully");

    // Create vector from the allocated memory - RAII will handle cleanup
    uint8_t* rawPtr = static_cast<uint8_t*>(reportPtr.get());
    std::vector<uint8_t> report(rawPtr, rawPtr + reportSize);
 
    // DEBUG: Log before returning
    veil::vtl1::vtl0_functions::internal::debug_print(L"DEBUG: userboundkey_get_attestation_report returning successfully");

    auto sessionInfo = veil::vtl1::userboundkey::ConvertFromSessionHandle(std::move(sessionHandle));
    return veil_abi::Types::attestationReportAndSessionInfo {std::move(report), sessionInfo};
}

void userboundkey_close_session(_In_ uintptr_t session_info)
{
    veil::vtl1::vtl0_functions::internal::debug_print(L"DEBUG: userboundkey_close_session called with session: 0x" + std::to_wstring(session_info));
    
    if (session_info != 0)
    {
        // Convert back to session handle and use RAII for cleanup
        auto sessionHandle = veil::vtl1::userboundkey::ConvertToSessionHandle(session_info);
        veil::vtl1::vtl0_functions::internal::debug_print(L"DEBUG: userboundkey_close_session - Session handle cleaned up via RAII");
        // sessionHandle destructor will automatically call CloseUserBoundKeySession
    }
    else
    {
        veil::vtl1::vtl0_functions::internal::debug_print(L"DEBUG: userboundkey_close_session - Session info is null, nothing to clean up");
    }
}
}

namespace veil::vtl1::implementation::userboundkey::callouts
{
    veil_abi::Types::credentialAndSessionInfo userboundkey_establish_session_for_create(
        _In_ const void* enclave, 
        _In_ const std::wstring& key_name, 
        _In_ const uintptr_t ecdh_protocol, 
        _In_ const std::wstring& message, 
        _In_ const uintptr_t window_id, 
        _In_ const veil::vtl1::userboundkey::keyCredentialCacheConfig& cache_config,
        _In_ const uint32_t key_credential_creation_option)
    {
        // Convert cache_config to the correct type
        auto abi_cache_config = veil::vtl1::userboundkey::ConvertCacheConfig(cache_config);

        return veil_abi::Untrusted::Stubs::userboundkey_establish_session_for_create(
            reinterpret_cast<uintptr_t>(enclave),
            key_name,
            ecdh_protocol,
            message,
            window_id,
            abi_cache_config,
            key_credential_creation_option);
    }

    veil_abi::Types::credentialAndSessionInfo userboundkey_establish_session_for_load(
        _In_ const void* enclave,
        _In_ const std::wstring& key_name,
        _In_ const std::wstring& message, 
        _In_ const uintptr_t window_id)
    {
        return veil_abi::Untrusted::Stubs::userboundkey_establish_session_for_load(
            reinterpret_cast<uintptr_t>(enclave),
            key_name,
            message,
            window_id);
    }

    // Function to extract authorization context from credential
    std::vector<std::uint8_t> userboundkey_get_authorization_context_from_credential(
        _In_ const uintptr_t credential,
        _In_ const std::vector<std::uint8_t>& public_key,
        _In_ const std::wstring& message,
        _In_ const uintptr_t window_id)
    {
        return veil_abi::Untrusted::Stubs::userboundkey_get_authorization_context_from_credential(
            credential,
            public_key,
            message,
            window_id);
    }

    std::vector<std::uint8_t> userboundkey_get_secret_from_credential(
        _In_ const uintptr_t credential,
        _In_ const std::vector<std::uint8_t>& public_key,
        _In_ const std::wstring& message,
        _In_ const uintptr_t window_id)
    {
        return veil_abi::Untrusted::Stubs::userboundkey_get_secret_from_credential(
            credential,
            public_key,
            message,
            window_id);
    }

    // Format a key name with SID information - calls VTL0
    std::wstring userboundkey_format_key_name(
        _In_ const std::wstring& key_name)
    {
        return veil_abi::Untrusted::Stubs::userboundkey_format_key_name(key_name);
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
            // CloseUserBoundKeyAuthContext returns HRESULT, but we're in a noexcept context
            // so we ignore the return value
            (void)CloseUserBoundKeyAuthContext(handle);
        }
    }

    // Helper function to safely read a uint32_t from a byte buffer
    inline uint32_t read_uint32(const uint8_t* ptr)
    {
        uint32_t value;
        std::memcpy(&value, ptr, sizeof(value));
        return value;
    }

    inline void validate_formatted_key_name(
        const std::wstring& formattedKeyName, 
        const std::wstring& originalKeyName,
        const wchar_t* functionName)
    {
        // Expected format: {SID}//{SID}//{keyName}
        std::wstring expectedSuffix = L"//" + originalKeyName;
    
        veil::vtl1::vtl0_functions::internal::debug_print((std::wstring(functionName) + L" - Validating formatted key name security").c_str());
        veil::vtl1::vtl0_functions::internal::debug_print((std::wstring(functionName) + L" - Expected suffix: " + expectedSuffix + L", Formatted: " + formattedKeyName).c_str());
    
        if (!formattedKeyName.ends_with(expectedSuffix))
        {
            veil::vtl1::vtl0_functions::internal::debug_print((std::wstring(functionName) + L" - ERROR: Formatted key name does not end with expected pattern. Expected suffix: " + expectedSuffix + L", Formatted: " + formattedKeyName).c_str());
            veil::vtl1::vtl0_functions::internal::debug_print((std::wstring(functionName) + L" - ERROR: This could be a security attack attempt with malicious key name").c_str());
            THROW_HR(E_ACCESSDENIED);
        }
     
        veil::vtl1::vtl0_functions::internal::debug_print((std::wstring(functionName) + L" - Key name security validation passed (suffix check)").c_str());
    }
}

using unique_auth_context_handle = 
    wil::unique_any<USER_BOUND_KEY_AUTH_CONTEXT_HANDLE, decltype(&::veil::vtl1::userboundkey::close_auth_context_handle), ::veil::vtl1::userboundkey::close_auth_context_handle>;

std::vector<uint8_t> GetEphemeralPublicKeyBytesFromBoundKeyBytes(std::span<const uint8_t> boundKeyBytes)
{
    // The bound key structure is created in CreateBoundKeyStructure() in veinterop.dll:
    // [enclave public key blob size (4 bytes)]
    // [enclave public key blob]  

    // We need to extract the enclave public key blob (the "ephemeral public key")

    veil::vtl1::vtl0_functions::internal::debug_print((L"DEBUG: GetEphemeralPublicKeyBytesFromBoundKeyBytes - Starting with boundKeyBytes.size(): " + std::to_wstring(boundKeyBytes.size())).c_str());

    if (boundKeyBytes.size() < sizeof(uint32_t))
    {
        veil::vtl1::vtl0_functions::internal::debug_print(L"ERROR: GetEphemeralPublicKeyBytesFromBoundKeyBytes - Bound key bytes too small - missing size field");
        throw std::invalid_argument("Bound key bytes too small - missing size field");
    }

    const uint8_t* currentPosition = boundKeyBytes.data();

    // Read the enclave public key blob size (first 4 bytes)
    uint32_t enclavePublicKeyBlobSize = read_uint32(currentPosition);
    currentPosition += sizeof(uint32_t);

    veil::vtl1::vtl0_functions::internal::debug_print((L"DEBUG: GetEphemeralPublicKeyBytesFromBoundKeyBytes - enclavePublicKeyBlobSize: " + std::to_wstring(enclavePublicKeyBlobSize)).c_str());

    // Validate that we have enough data for the full public key blob
    size_t remainingBytes = boundKeyBytes.size() - sizeof(uint32_t);
    veil::vtl1::vtl0_functions::internal::debug_print((L"DEBUG: GetEphemeralPublicKeyBytesFromBoundKeyBytes - remainingBytes: " + std::to_wstring(remainingBytes)).c_str());

    if (remainingBytes < enclavePublicKeyBlobSize)
    {
        veil::vtl1::vtl0_functions::internal::debug_print((L"ERROR: GetEphemeralPublicKeyBytesFromBoundKeyBytes - Insufficient data for public key blob. Need: " + std::to_wstring(enclavePublicKeyBlobSize) + L", Have: " + std::to_wstring(remainingBytes)).c_str());
        throw std::runtime_error("Bound key bytes corrupted - insufficient data for public key blob");
    }

    // Additional validation: check for unreasonably large public key size
    if (enclavePublicKeyBlobSize > remainingBytes || enclavePublicKeyBlobSize == 0)
    {
        veil::vtl1::vtl0_functions::internal::debug_print((L"ERROR: GetEphemeralPublicKeyBytesFromBoundKeyBytes - Invalid public key blob size: " + std::to_wstring(enclavePublicKeyBlobSize) + L" (remainingBytes: " + std::to_wstring(remainingBytes) + L")").c_str());

        // Add hex dump of first 16 bytes for debugging
        size_t maxBytes = boundKeyBytes.size() < 16 ? boundKeyBytes.size() : 16;
        std::vector<uint8_t> firstBytes(boundKeyBytes.begin(), boundKeyBytes.begin() + maxBytes);
        auto hexDump = CreateHexDump(firstBytes, L"First 16 bytes of boundKeyBytes");
        veil::vtl1::vtl0_functions::internal::debug_print(hexDump.c_str());

        throw std::runtime_error("Bound key bytes corrupted - invalid public key blob size");
    }

    // Extract the enclave public key blob
    std::vector<uint8_t> ephemeralPublicKey(currentPosition, currentPosition + enclavePublicKeyBlobSize);

    veil::vtl1::vtl0_functions::internal::debug_print((L"DEBUG: GetEphemeralPublicKeyBytesFromBoundKeyBytes - Successfully extracted ephemeral public key, size: " + std::to_wstring(ephemeralPublicKey.size())).c_str());

    return ephemeralPublicKey;
}

wil::secure_vector<uint8_t> create_user_bound_key(
    const std::wstring& keyName,
    const veil::vtl1::userboundkey::keyCredentialCacheConfig& cacheConfig,
    const std::wstring& message,
    uintptr_t windowId,
    ENCLAVE_SEALING_IDENTITY_POLICY sealingPolicy,
    uint32_t runtimePolicy,
    uint32_t keyCredentialCreationOption)
{
    veil::vtl1::debug::debug_print(L"DEBUG: create_user_bound_key - Generating symmetric key");

    // Generate random symmetric key
    auto userkeyBytes = veil::vtl1::crypto::generate_symmetric_key_bytes();

    // Delegate to the overload that accepts custom key bytes
    auto result = create_user_bound_key(
        keyName,
        cacheConfig,
        message,
        windowId,
        sealingPolicy,
        runtimePolicy,
        keyCredentialCreationOption,
        userkeyBytes);
    return result;
}

// Overload function to support custom key bytes (for asymmetric keys)
wil::secure_vector<uint8_t> create_user_bound_key(
    const std::wstring& keyName,
    const veil::vtl1::userboundkey::keyCredentialCacheConfig& cacheConfig,
    const std::wstring& message,
    uintptr_t windowId,
    ENCLAVE_SEALING_IDENTITY_POLICY sealingPolicy,
    uint32_t runtimePolicy,
    uint32_t keyCredentialCreationOption,
    std::span<const uint8_t> customKeyBytes)
{
    veil::vtl1::vtl0_functions::internal::debug_print(L"DEBUG: create_user_bound_key (with custom key bytes) - Function entered");
    
    try
    {
        // Convert cacheConfig to the type expected by the callback
        auto abi_cache_config = ConvertCacheConfig(cacheConfig);
        wil::unique_process_heap_ptr<void> encryptedKcmRequestRac; // RAII wrapper for automatic cleanup
        uint32_t encryptedKcmRequestRacSize = 0;
        uint64_t localNonce = 0; // captures the nonce used in the encrypted request, will be used in the corresponding decrypt call

        // Format the key name before establishing session
        veil::vtl1::vtl0_functions::internal::debug_print(L"DEBUG: create_user_bound_key - Formatting key name");
        std::wstring formattedKeyName = veil::vtl1::implementation::userboundkey::callouts::userboundkey_format_key_name(keyName);
   
        veil::vtl1::vtl0_functions::internal::debug_print((L"DEBUG: create_user_bound_key - formattedKeyName: " + formattedKeyName).c_str());

        // SECURITY: Validate formatted key name to prevent malicious key name attacks
        validate_formatted_key_name(formattedKeyName, keyName, L"create_user_bound_key");

        // SESSION
        veil::vtl1::debug::debug_print(L"DEBUG: create_user_bound_key - About to call userboundkey_establish_session_for_create");

        void* enclave = veil::vtl1::enclave_information().BaseAddress;
        auto credentialAndSessionInfo = veil::vtl1::implementation::userboundkey::callouts::userboundkey_establish_session_for_create(
            enclave,
            keyName,
            reinterpret_cast<uintptr_t>(BCRYPT_ECDH_P384_ALG_HANDLE),
            message,
            windowId,
            cacheConfig,
            keyCredentialCreationOption);

        veil::vtl1::vtl0_functions::internal::debug_print(L"DEBUG: create_user_bound_key - Received credential and session info");

        // Use RAII wrapper to prevent leaks
        unique_credential credentialWrapper(credentialAndSessionInfo.credential);
        unique_sessionhandle sessionHandle = ConvertToSessionHandle(credentialAndSessionInfo.sessionInfo);

        veil::vtl1::vtl0_functions::internal::debug_print((L"DEBUG: create_user_bound_key - credential pointer: 0x" + std::to_wstring(credentialWrapper.get())).c_str());

        // Call to veinterop to create the encrypted KCM request for RetrieveAuthorizationContext
        // Note: encryptedKcmRequestRac and encryptedKcmRequestRacSize are already declared at the top of the function

        // Use the function that accepts session handle and handles nonce manipulation internally
        THROW_IF_FAILED(CreateUserBoundKeyRequestForRetrieveAuthorizationContext(
            sessionHandle.get(),  // Pass session handle - nonce manipulation is handled internally
            formattedKeyName.c_str(),
            &localNonce,
            wil::out_param(encryptedKcmRequestRac),
            &encryptedKcmRequestRacSize)); // OS CALL

        // Convert the result to vector for the callback
        std::vector<uint8_t> encryptedKcmRequestForRetrieveAuthorizationContext;
        encryptedKcmRequestForRetrieveAuthorizationContext.assign(
            static_cast<uint8_t*>(encryptedKcmRequestRac.get()),
            static_cast<uint8_t*>(encryptedKcmRequestRac.get()) + encryptedKcmRequestRacSize);

        // Second call to extract authorization context from credential
        veil::vtl1::vtl0_functions::internal::debug_print(L"DEBUG: create_user_bound_key - About to call userboundkey_get_authorization_context_from_credential");

        auto authContextBlob = veil::vtl1::implementation::userboundkey::callouts::userboundkey_get_authorization_context_from_credential(
            credentialWrapper.get(),
            encryptedKcmRequestForRetrieveAuthorizationContext,
            message,
            windowId);

        veil::vtl1::vtl0_functions::internal::debug_print(L"DEBUG: create_user_bound_key - userboundkey_get_authorization_context_from_credential completed");

        // AUTH CONTEXT
        unique_auth_context_handle authContext;
        THROW_IF_FAILED(GetUserBoundKeyAuthContext(
            sessionHandle.get(),
            authContextBlob.data(),
            static_cast<uint32_t>(authContextBlob.size()),
            localNonce,
            authContext.put()
        )); // OS CALL
  
        veil::vtl1::vtl0_functions::internal::debug_print(L"DEBUG: create_user_bound_key - GetUserBoundKeyAuthContext completed");

        // Validate
        USER_BOUND_KEY_AUTH_CONTEXT_PROPERTY propCacheConfig;
        propCacheConfig.name = UserBoundKeyAuthContextPropertyCacheConfig;
        propCacheConfig.size = sizeof(cacheConfig);
        propCacheConfig.value = &(const_cast<veil::vtl1::userboundkey::keyCredentialCacheConfig&>(cacheConfig));
        THROW_IF_FAILED(ValidateUserBoundKeyAuthContext(
            formattedKeyName.c_str(),
            authContext.get(),
            1,
            &propCacheConfig)); // OS CALL
        veil::vtl1::vtl0_functions::internal::debug_print(L"DEBUG: create_user_bound_key - ValidateUserBoundKeyAuthContext completed");

        // USE CUSTOM KEY BYTES instead of generating symmetric key
        veil::vtl1::vtl0_functions::internal::debug_print((L"DEBUG: create_user_bound_key - Using custom key bytes, size: " + std::to_wstring(customKeyBytes.size())).c_str());
        std::vector<uint8_t> userkeyBytes(customKeyBytes.begin(), customKeyBytes.end());

        // ENCRYPT USERKEY  
        wil::unique_process_heap_ptr<void> boundKey;
        uint32_t boundKeySize = 0;
        veil::vtl1::vtl0_functions::internal::debug_print(L"DEBUG: create_user_bound_key - About to call ProtectUserBoundKey");
        THROW_IF_FAILED(ProtectUserBoundKey(
            authContext.get(),
            userkeyBytes.data(),
            static_cast<uint32_t>(userkeyBytes.size()),
            wil::out_param(boundKey),
            &boundKeySize   // Will be set to actual size by ProtectUserBoundKey
        )); // OS CALL
        veil::vtl1::vtl0_functions::internal::debug_print((L"DEBUG: create_user_bound_key - ProtectUserBoundKey returned boundKey size: " + std::to_wstring(boundKeySize)).c_str());

        // Convert dynamically allocated buffer to vector for sealing
        std::vector<uint8_t> boundKeyBytes(
            static_cast<uint8_t*>(boundKey.get()),
            static_cast<uint8_t*>(boundKey.get()) + boundKeySize
        );

        // SEAL
        auto sealedKeyMaterial = veil::vtl1::crypto::seal_data(boundKeyBytes, sealingPolicy, runtimePolicy);
        veil::vtl1::vtl0_functions::internal::debug_print(L"DEBUG: create_user_bound_key - Function completed successfully");
        
        return sealedKeyMaterial;
    }
    catch (const std::exception& e)
    {
        // Convert exception message to wide string for debug printing
        std::string error_msg = e.what();
        std::wstring werror_msg(error_msg.begin(), error_msg.end());
        veil::vtl1::vtl0_functions::internal::debug_print((L"ERROR: create_user_bound_key - Exception caught: " + werror_msg).c_str());
        throw; // Re-throw the exception
    }
    catch (...)
    {
        veil::vtl1::vtl0_functions::internal::debug_print(L"ERROR: create_user_bound_key - Unknown exception caught");      
        throw; // Re-throw the exception
    }
}

std::vector<uint8_t> load_user_bound_key(
    const std::wstring& keyName,
    const veil::vtl1::userboundkey::keyCredentialCacheConfig& cacheConfig,
    const std::wstring& message,
    uintptr_t windowId,
    const std::vector<uint8_t>& sealedBoundKeyBytes,
    _Out_ bool& needsReseal)
{
    veil::vtl1::vtl0_functions::internal::debug_print(L"DEBUG: load_user_bound_key - Function entered");
    
    // Initialize output parameter
    needsReseal = false;
    
    try
    {
        uint64_t localNonce = 0; // captures the nonce used in the encrypted request, will be used in the corresponding decrypt call

        // UNSEAL
        veil::vtl1::vtl0_functions::internal::debug_print(L"DEBUG: load_user_bound_key - About to call unseal_data");
        veil::vtl1::vtl0_functions::internal::debug_print((L"DEBUG: load_user_bound_key - sealedBoundKeyBytes size: " + std::to_wstring(sealedBoundKeyBytes.size())).c_str());

        auto [boundKeyBytes, unsealingFlags] = veil::vtl1::crypto::unseal_data(sealedBoundKeyBytes);

        veil::vtl1::vtl0_functions::internal::debug_print(L"DEBUG: load_user_bound_key - unseal_data completed successfully");     
        veil::vtl1::vtl0_functions::internal::debug_print((L"DEBUG: load_user_bound_key - boundKeyBytes size: " + std::to_wstring(boundKeyBytes.size())).c_str());
        veil::vtl1::vtl0_functions::internal::debug_print((L"DEBUG: load_user_bound_key - unsealingFlags: 0x" + std::to_wstring(unsealingFlags)).c_str());

        // Check if the sealing key is stale and data needs to to be re-sealed
        if (unsealingFlags & ENCLAVE_UNSEAL_FLAG_STALE_KEY)
        {
            veil::vtl1::vtl0_functions::internal::debug_print(L"ERROR: load_user_bound_key - Stale sealing key detected, operation failed");
            veil::vtl1::vtl0_functions::internal::debug_print(L"ERROR: load_user_bound_key - Caller must handle re-sealing using reseal_user_bound_key function");
            veil::vtl1::vtl0_functions::internal::debug_print(L"ERROR: load_user_bound_key - This is a security requirement to ensure data integrity");
          
            // Set the needsReseal flag for informational purposes
            needsReseal = true;
 
            // Fail the operation - caller must explicitly handle resealing
            THROW_HR_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), 
                "Stale sealing key detected. Caller must re-seal the data using reseal_user_bound_key before attempting to load.");
        }
        std::vector<uint8_t> ephemeralPublicKeyBytes = GetEphemeralPublicKeyBytesFromBoundKeyBytes(boundKeyBytes);
        veil::vtl1::vtl0_functions::internal::debug_print((L"DEBUG: load_user_bound_key - ephemeralPublicKeyBytes size: " + std::to_wstring(ephemeralPublicKeyBytes.size())).c_str());

        // Format the key name before establishing session
        veil::vtl1::vtl0_functions::internal::debug_print(L"DEBUG: load_user_bound_key - Formatting key name");
        std::wstring formattedKeyName = veil::vtl1::implementation::userboundkey::callouts::userboundkey_format_key_name(keyName);
        veil::vtl1::vtl0_functions::internal::debug_print((L"DEBUG: load_user_bound_key - formattedKeyName: " + formattedKeyName).c_str());

        // SECURITY: Validate formatted key name to prevent malicious key name attacks
        validate_formatted_key_name(formattedKeyName, keyName, L"load_user_bound_key");

        // SESSION - First call to get credential and sessionInfo
        veil::vtl1::vtl0_functions::internal::debug_print(L"DEBUG: load_user_bound_key - About to call userboundkey_establish_session_for_load");

        void* enclave = veil::vtl1::enclave_information().BaseAddress;
        auto credentialAndSessionInfo = veil::vtl1::implementation::userboundkey::callouts::userboundkey_establish_session_for_load(
            enclave,
            keyName,
            message,
            windowId);

        veil::vtl1::vtl0_functions::internal::debug_print(L"DEBUG: load_user_bound_key - userboundkey_establish_session_for_load completed");

        // Use RAII wrapper to prevent leaks
        unique_credential credentialWrapper(credentialAndSessionInfo.credential);
        unique_sessionhandle sessionHandle = ConvertToSessionHandle(credentialAndSessionInfo.sessionInfo);

        veil::vtl1::vtl0_functions::internal::debug_print((L"DEBUG: load_user_bound_key - credential pointer: 0x" + std::to_wstring(credentialWrapper.get())).c_str());

        // Call to veinterop to create the encrypted KCM request for RetrieveAuthorizationContext
        wil::unique_process_heap_ptr<void> encryptedKcmRequestRac;
        uint32_t encryptedKcmRequestRacSize = 0;

        // Call to veinterop to create the encrypted KCM request for DeriveSharedSecret
        wil::unique_process_heap_ptr<void> encryptedKcmRequestDss;
        uint32_t encryptedKcmRequestDssSize = 0;

        // Use the function that accepts session handle and handles nonce manipulation internally
        THROW_IF_FAILED(CreateUserBoundKeyRequestForRetrieveAuthorizationContext(
            sessionHandle.get(),// Pass session handle - nonce manipulation is handled internally
            formattedKeyName.c_str(),
            &localNonce,
            wil::out_param(encryptedKcmRequestRac), 
            &encryptedKcmRequestRacSize)); // OS CALL

        // Convert the result to vector for the callback
        std::vector<uint8_t> encryptedKcmRequestForRetrieveAuthorizationContext;
        encryptedKcmRequestForRetrieveAuthorizationContext.assign(
            static_cast<uint8_t*>(encryptedKcmRequestRac.get()),
            static_cast<uint8_t*>(encryptedKcmRequestRac.get()) + encryptedKcmRequestRacSize);

        // Second call to extract authorization context from credential
        veil::vtl1::vtl0_functions::internal::debug_print(L"DEBUG: load_user_bound_key - About to call userboundkey_get_authorization_context_from_credential");

        auto authContextBlob = veil::vtl1::implementation::userboundkey::callouts::userboundkey_get_authorization_context_from_credential(
            credentialWrapper.get(),  // VTL0 callbacks handle their own reference management
            encryptedKcmRequestForRetrieveAuthorizationContext,
            message,
            windowId);

        veil::vtl1::vtl0_functions::internal::debug_print(L"DEBUG: load_user_bound_key - userboundkey_get_authorization_context_from_credential completed");
        veil::vtl1::vtl0_functions::internal::debug_print((L"DEBUG: load_user_bound_key - authContextBlob size: " + std::to_wstring(authContextBlob.size())).c_str());

        // AUTH CONTEXT
        veil::vtl1::vtl0_functions::internal::debug_print(L"DEBUG: load_user_bound_key - About to call GetUserBoundKeyAuthContext");
        unique_auth_context_handle authContext;
        THROW_IF_FAILED(GetUserBoundKeyAuthContext(
            sessionHandle.get(),
            authContextBlob.data(),
            static_cast<uint32_t>(authContextBlob.size()),
            localNonce,
            authContext.put())); // OS CALL
        veil::vtl1::vtl0_functions::internal::debug_print(L"DEBUG: load_user_bound_key - GetUserBoundKeyAuthContext completed");

        // Validate
        veil::vtl1::vtl0_functions::internal::debug_print(L"DEBUG: load_user_bound_key - About to validate auth context");
        USER_BOUND_KEY_AUTH_CONTEXT_PROPERTY propCacheConfig;
        propCacheConfig.name = UserBoundKeyAuthContextPropertyCacheConfig;
        propCacheConfig.size = sizeof(cacheConfig);
        propCacheConfig.value = &(const_cast<veil::vtl1::userboundkey::keyCredentialCacheConfig&>(cacheConfig));
        THROW_IF_FAILED(ValidateUserBoundKeyAuthContext(
            formattedKeyName.c_str(),
            authContext.get(),
            1,
            &propCacheConfig)); // OS CALL
        veil::vtl1::vtl0_functions::internal::debug_print(L"DEBUG: load_user_bound_key - Auth context validation completed");

        // Use the function that accepts session handle and handles nonce manipulation internally
        THROW_IF_FAILED(CreateUserBoundKeyRequestForDeriveSharedSecret(
            sessionHandle.get(),  // Pass session handle - nonce manipulation is handled internally
            formattedKeyName.c_str(),
            ephemeralPublicKeyBytes.data(),
            static_cast<uint32_t>(ephemeralPublicKeyBytes.size()),
            &localNonce,
            wil::out_param(encryptedKcmRequestDss),
            &encryptedKcmRequestDssSize)); // OS CALL

        // Convert the result to vector for the callback
        std::vector<uint8_t> encryptedKcmRequestForDeriveSharedSecret;
        encryptedKcmRequestForDeriveSharedSecret.assign(
            static_cast<uint8_t*>(encryptedKcmRequestDss.get()),
            static_cast<uint8_t*>(encryptedKcmRequestDss.get()) + encryptedKcmRequestDssSize);

        // Second call to extract secret from credential
        veil::vtl1::vtl0_functions::internal::debug_print(L"DEBUG: load_user_bound_key - About to call userboundkey_get_secret_from_credential");

        auto secret = veil::vtl1::implementation::userboundkey::callouts::userboundkey_get_secret_from_credential(
            credentialWrapper.get(),
            encryptedKcmRequestForDeriveSharedSecret,
            message,
            windowId);

        veil::vtl1::vtl0_functions::internal::debug_print(L"DEBUG: load_user_bound_key - userboundkey_get_secret_from_credential completed");
        veil::vtl1::vtl0_functions::internal::debug_print((L"DEBUG: load_user_bound_key - secret size: " + std::to_wstring(secret.size())).c_str());

        // DECRYPT USERKEY
        veil::vtl1::vtl0_functions::internal::debug_print(L"DEBUG: load_user_bound_key - About to call UnprotectUserBoundKey");
        uint32_t userkeySize = 0;
        wil::unique_process_heap_ptr<void> userkey;

        // Use the existing session handle for the API call
        THROW_IF_FAILED(UnprotectUserBoundKey(
            sessionHandle.get(),
            authContext.get(),
            secret.data(),
            static_cast<uint32_t>(secret.size()),
            boundKeyBytes.data(),
            static_cast<uint32_t>(boundKeyBytes.size()),
            localNonce,
            wil::out_param(userkey),
            &userkeySize)); // OS CALL
        veil::vtl1::vtl0_functions::internal::debug_print(L"DEBUG: load_user_bound_key - UnprotectUserBoundKey completed");

        std::vector<uint8_t> userkeyBytes(static_cast<uint8_t*>(userkey.get()), static_cast<uint8_t*>(userkey.get()) + userkeySize);
        // Memory automatically freed by unique_process_heap_ptr destructor

        veil::vtl1::vtl0_functions::internal::debug_print(L"DEBUG: load_user_bound_key - Function completed successfully");

        return userkeyBytes;
    }
    catch (const std::exception& e)
    {
        // Convert exception message to wide string for debug printing
        std::string error_msg = e.what();
        std::wstring werror_msg(error_msg.begin(), error_msg.end());
        veil::vtl1::vtl0_functions::internal::debug_print((L"ERROR: load_user_bound_key - Exception caught: " + werror_msg).c_str());
        throw; // Re-throw the exception
    }
    catch (...)
    {
        veil::vtl1::vtl0_functions::internal::debug_print(L"ERROR: load_user_bound_key - Unknown exception caught");
        throw; // Re-throw the exception
    }
}

std::vector<uint8_t> reseal_user_bound_key(
    const std::vector<uint8_t>& boundKeyBytes,
    ENCLAVE_SEALING_IDENTITY_POLICY sealingPolicy,
    uint32_t runtimePolicy)
{
    veil::vtl1::vtl0_functions::internal::debug_print(L"DEBUG: reseal_user_bound_key - Function entered");
    veil::vtl1::vtl0_functions::internal::debug_print((L"DEBUG: reseal_user_bound_key - boundKeyBytes size: " + std::to_wstring(boundKeyBytes.size())).c_str());
    veil::vtl1::vtl0_functions::internal::debug_print((L"DEBUG: reseal_user_bound_key - sealingPolicy: " + std::to_wstring(static_cast<uint32_t>(sealingPolicy))).c_str());
    veil::vtl1::vtl0_functions::internal::debug_print((L"DEBUG: reseal_user_bound_key - runtimePolicy: 0x" + std::to_wstring(runtimePolicy)).c_str());
    
    try
    {
        // Re-seal the bound key bytes with current enclave identity
        auto resealedData = veil::vtl1::crypto::seal_data(
            boundKeyBytes, 
            sealingPolicy,
            runtimePolicy);
            
        veil::vtl1::vtl0_functions::internal::debug_print((L"DEBUG: reseal_user_bound_key - Successfully re-sealed bound key, new size: " + std::to_wstring(resealedData.size())).c_str());
        veil::vtl1::vtl0_functions::internal::debug_print(L"DEBUG: reseal_user_bound_key - Function completed successfully");
        
        return std::vector<uint8_t>(resealedData.begin(), resealedData.end());
    }
    catch (const std::exception& e)
    {
        // Convert exception message to wide string for debug printing
        std::string error_msg = e.what();
        std::wstring werror_msg(error_msg.begin(), error_msg.end());
        veil::vtl1::vtl0_functions::internal::debug_print((L"ERROR: reseal_user_bound_key - Exception caught: " + werror_msg).c_str());
        throw; // Re-throw the exception
    }
    catch (...)
    {
        veil::vtl1::vtl0_functions::internal::debug_print(L"ERROR: reseal_user_bound_key - Unknown exception caught");
        throw; // Re-throw the exception
    }
}
} // namespace veil::vtl1::userboundkey
