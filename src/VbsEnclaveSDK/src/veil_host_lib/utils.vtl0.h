// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <mutex>
#include <string>
#include <iostream>

namespace veil::vtl0::implementation
{
    extern std::mutex g_printMutex;
}

namespace veil::vtl0::implementation::debug
{
    // Debug printing function that only outputs in debug mode
    inline void w_debug_print(const std::wstring& str)
    {
        #ifdef _VEIL_INTERNAL_DEBUG
            std::wcout << str << std::endl;
        #endif
    }

    // Debug printing function for narrow strings
    inline void debug_print(const std::string& str)
    {
        #ifdef _VEIL_INTERNAL_DEBUG
            std::cout << str << std::endl;
        #endif
    }
}
