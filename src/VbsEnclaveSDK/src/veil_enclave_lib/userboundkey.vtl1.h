#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <wil/resource.h>
#include "future.vtl1.h"
#include "object_table.vtl1.h"
#include "vengcdll.h" // For KEY_CREDENTIAL_CACHE_CONFIG and other OS types

// Forward declarations for the auto-generated types
namespace DeveloperTypes
{
    struct authContextBlobAndSessionKeyPtr;
    struct secretAndAuthorizationContextAndSessionKeyPtr;
    struct keyCredentialCacheConfig;
}

namespace veil::vtl1::implementation::userboundkey::callouts
{
    DeveloperTypes::authContextBlobAndSessionKeyPtr userboundkey_establish_session_for_create_callback(
        _In_ const void* enclave,
        _In_ const std::wstring& key_name,
        _In_ const uintptr_t ecdh_protocol,
        _In_ const std::wstring& message,
        _In_ const uintptr_t window_id,
        _In_ const DeveloperTypes::keyCredentialCacheConfig& cache_config);

    DeveloperTypes::secretAndAuthorizationContextAndSessionKeyPtr userboundkey_establish_session_for_load_callback(
        _In_ const void* enclave,
        _In_ const std::wstring& key_name,
        _In_ const std::vector<std::uint8_t>& public_key,
        _In_ const std::wstring& message,
        _In_ const uintptr_t window_id);
}

namespace veil::vtl1::userboundkey
{
    wil::secure_vector<uint8_t> enclave_create_user_bound_key(
        const std::wstring& keyName,
        KEY_CREDENTIAL_CACHE_CONFIG& cacheConfig,
        const std::wstring& message,
        uintptr_t windowId,
        ENCLAVE_SEALING_IDENTITY_POLICY sealingPolicy);

    std::vector<uint8_t> enclave_load_user_bound_key(
        const std::wstring& keyName,
        KEY_CREDENTIAL_CACHE_CONFIG& cacheConfig,
        const std::wstring& message,
        uintptr_t windowId,
        std::vector<uint8_t>& sealedBoundKeyBytes);
}
