#pragma once

#include "veil.any.h"

namespace veil::vtl1::implementation
{
    void register_callback(veil::implementation::callback_t* callbackAddresses);
    veil::implementation::callback_t get_callback(veil::implementation::callback_id callbackId);
}
