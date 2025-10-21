#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <wil/resource.h>
#include "future.vtl1.h"
#include <veinterop_kcm.h>
#include <VbsEnclave\Enclave\Implementation\Types.h>

// Forward declarations for the auto-generated types
namespace DeveloperTypes
{
    struct keyCredentialCacheConfig;
}

namespace veil::vtl1::userboundkey
{
    wil::secure_vector<uint8_t> enclave_create_user_bound_key(
        const std::wstring& keyName,
        DeveloperTypes::keyCredentialCacheConfig& cacheConfig,
        const std::wstring& message,
        uintptr_t windowId,
        ENCLAVE_SEALING_IDENTITY_POLICY sealingPolicy);

    std::vector<uint8_t> enclave_load_user_bound_key(
        const std::wstring& keyName,
        DeveloperTypes::keyCredentialCacheConfig& cacheConfig,
        const std::wstring& message,
        uintptr_t windowId,
        std::vector<uint8_t>& sealedBoundKeyBytes);
}
