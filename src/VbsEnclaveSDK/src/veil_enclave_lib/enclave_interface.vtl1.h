// <copyright placeholder>

#pragma once

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
        
        // API
        std::vector<uint8_t> owner_id();
    }
}
