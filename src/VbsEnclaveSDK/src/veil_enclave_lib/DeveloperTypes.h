#pragma once

#include <stdexcept>

// Define the global developer types namespace structure BEFORE including VbsEnclave headers
// to ensure it doesn't conflict with the VbsEnclave types
namespace veil::vtl1::developer_types
{
    struct keyCredentialCacheConfig
    {
        std::uint32_t cacheOption {};
        std::uint32_t cacheTimeoutInSeconds {};
        std::uint32_t cacheUsageCount {};
    };
}
