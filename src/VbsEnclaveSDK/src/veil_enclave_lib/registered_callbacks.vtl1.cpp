// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "pch.h"

#include <map>
#include <string>

#include "registered_callbacks.vtl1.h"

//
// TODO: SECURITY
//

namespace veil::vtl1::implementation
{
    veil::implementation::callback_t* g_callbackTable{};

    void register_callbacks(veil::implementation::callback_t* callbackAddresses) noexcept
    {
        g_callbackTable = callbackAddresses;
    }

    veil::implementation::callback_t get_callback(veil::implementation::callback_id callbackId)
    {
        return g_callbackTable[static_cast<uint32_t>(callbackId)];
    }

}
