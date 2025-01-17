#pragma once

#include <functional>
#include <span>
#include <vector>

#include "utils.vtl1.h"

namespace veil::vtl1
{
    namespace enclave_interface
    {
        struct enclave_info
        {
            std::vector<uint8_t> owner_id;
        };

        // API: Config
        namespace config
        {
            HRESULT set_allowed_package_family_names(std::span<PCWSTR> allowedPackageFamilyNames) noexcept;
            HRESULT set_instancing_enforcement_callback(std::function<HRESULT(std::span<const veil::vtl1::enclave_interface::enclave_info>)>&& callback) noexcept;
        }

        // API
        std::vector<uint8_t> owner_id();
        bool is_unlocked();
    }
}
