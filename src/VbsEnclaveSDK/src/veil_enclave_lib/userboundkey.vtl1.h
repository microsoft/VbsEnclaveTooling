#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <wil/resource.h>
#include "future.vtl1.h"
#include <veinterop_kcm.h>
#include <stdexcept>
#include <VbsEnclave\Enclave\Implementation\Types.h>

namespace veil::vtl1::userboundkey
{
    struct keyCredentialCacheConfig
    {
        std::uint32_t cacheOption {};
        std::uint32_t cacheTimeoutInSeconds {};
        std::uint32_t cacheUsageCount {};
    };

    wil::secure_vector<uint8_t> create_user_bound_key(
        const std::wstring& keyName,
        const veil::vtl1::userboundkey::keyCredentialCacheConfig& cacheConfig,
        const std::wstring& message,
        uintptr_t windowId,
        ENCLAVE_SEALING_IDENTITY_POLICY sealingPolicy,
        uint32_t runtimePolicy,
        uint32_t keyCredentialCreationOption);

    std::vector<uint8_t> load_user_bound_key(
        const std::wstring& keyName,
        const veil::vtl1::userboundkey::keyCredentialCacheConfig& cacheConfig,
        const std::wstring& message,
        uintptr_t windowId,
        const std::vector<uint8_t>& sealedBoundKeyBytes,
        _Out_ bool& needsReseal);

    std::vector<uint8_t> reseal_user_bound_key(
        const std::vector<uint8_t>& boundKeyBytes,
        ENCLAVE_SEALING_IDENTITY_POLICY sealingPolicy,
        uint32_t runtimePolicy);
}
