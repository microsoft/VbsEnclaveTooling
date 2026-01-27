#pragma once

#include "pch.h"
#include <vector>
#include <string>
#include <cstdint>
#include <wil/resource.h>
#include "future.vtl1.h"
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

    wil::secure_vector<uint8_t> create_user_bound_key(
        const std::wstring& keyName,
        const veil::vtl1::userboundkey::keyCredentialCacheConfig& cacheConfig,
        const std::wstring& message,
        uintptr_t windowId,
        ENCLAVE_SEALING_IDENTITY_POLICY sealingPolicy,
        uint32_t runtimePolicy,
        uint32_t keyCredentialCreationOption,
        std::span<const uint8_t> customKeyBytes);

    /// <summary>
    /// Loads a user-bound key from sealed bytes. FAILS if re-sealing is required.
    /// When the sealing key becomes stale, this function will fail with ERROR_INVALID_DATA.
    /// The caller must use reseal_user_bound_key to re-seal the data before attempting to load again.
    /// This ensures explicit handling of re-sealing scenarios for security and data integrity.
    std::vector<uint8_t> load_user_bound_key(
        const std::wstring& keyName,
        const veil::vtl1::userboundkey::keyCredentialCacheConfig& cacheConfig,
        const std::wstring& message,
        uintptr_t windowId,
        const std::vector<uint8_t>& sealedBoundKeyBytes,
        _Out_ bool& needsReseal);

    /// <summary>
    /// Re-seals previously sealed bound key data with the current enclave identity.
    /// This function first unseals the input data, then re-seals it with the specified policy.
    /// Used when the sealing key has rotated (detected by needsReseal flag from load_user_bound_key).
    /// </summary>
    /// <param name="sealedBoundKeyBytes">The sealed bound key bytes to reseal</param>
    /// <param name="sealingPolicy">The sealing identity policy for the new seal</param>
    /// <param name="runtimePolicy">The runtime policy flags</param>
    /// <returns>Newly sealed key material that can be stored and used with future loads</returns>
    std::vector<uint8_t> reseal_user_bound_key(
        const std::vector<uint8_t>& sealedBoundKeyBytes,
        ENCLAVE_SEALING_IDENTITY_POLICY sealingPolicy,
        uint32_t runtimePolicy);
}
