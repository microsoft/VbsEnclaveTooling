#pragma once

#include <stdexcept>

// Define the global DeveloperTypes namespace structure BEFORE including VbsEnclave headers
// to ensure it doesn't conflict with the VbsEnclave types
namespace DeveloperTypes
{
    struct keyCredentialCacheConfig
    {
        std::uint32_t cacheOption {};
        std::uint32_t cacheTimeoutInSeconds {};
        std::uint32_t cacheUsageCount {};
    };
}
