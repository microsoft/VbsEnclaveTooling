#pragma once

#include "veil.any.h"

namespace veil::vtl1::implementation
{
    void register_callback(veil::callback_t* callbackAddresses);
    veil::callback_t get_callback(veil::callback_id callbackId);
}
