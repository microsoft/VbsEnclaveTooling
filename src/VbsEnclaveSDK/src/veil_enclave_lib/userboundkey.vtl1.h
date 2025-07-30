#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <wil/resource.h>
#include "vengcdll.h" // For KEY_CREDENTIAL_CACHE_CONFIG and other OS types

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
