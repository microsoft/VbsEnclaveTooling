// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "veil.any.h"

namespace veil::vtl1::implementation
{
    void register_callbacks(veil::implementation::callback_t* callbackAddresses) noexcept;
    veil::implementation::callback_t get_callback(veil::implementation::callback_id callbackId);
}
