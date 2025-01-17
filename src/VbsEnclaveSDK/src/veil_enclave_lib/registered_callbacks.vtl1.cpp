#include "pch.h"

#include <map>
#include <string>

#include "registered_callbacks.vtl1.h"



namespace veil::vtl1::implementation
{
    veil::callback_t* g_callbackTable{};

    void register_callback(veil::callback_t* callbackAddresses)
    {
        // Register callback
        g_callbackTable = callbackAddresses;
    }

    veil::callback_t get_callback(veil::callback_id callbackId)
    {
        return g_callbackTable[static_cast<uint32_t>(callbackId)];
    }

}
