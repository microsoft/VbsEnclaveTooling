// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <string>
#include "vtl0_functions.vtl1.h"

// High-level debug interface that uses _VEIL_INTERNAL_DEBUG compile-time flag
namespace veil::vtl1::debug
{
    // Debug printing function that only outputs when _VEIL_INTERNAL_DEBUG is defined
    inline void internal_debug_print(const wchar_t* str)
    {
        #ifdef _VEIL_INTERNAL_DEBUG
            veil::vtl1::vtl0_functions::internal_debug_print(str);
        #else
            // Suppress unused parameter warning in release builds
            (void)str;
        #endif
    }

    // Debug printing function for std::wstring that only outputs when _VEIL_INTERNAL_DEBUG is defined
    inline void internal_debug_print(const std::wstring& str)
    {
        #ifdef _VEIL_INTERNAL_DEBUG
            veil::vtl1::vtl0_functions::internal_debug_print(str.c_str());
        #else
            // Suppress unused parameter warning in release builds
            (void)str;
        #endif
    }

    // Debug printing function for formatted strings that only outputs when _VEIL_INTERNAL_DEBUG is defined
    template<typename... Args>
    inline void internal_debug_printf(const wchar_t* format, Args&&... args)
    {
        #ifdef _VEIL_INTERNAL_DEBUG
            // Use a buffer to format the string
            wchar_t buffer[1024];
            swprintf_s(buffer, format, std::forward<Args>(args)...);
            veil::vtl1::vtl0_functions::internal_debug_print(buffer);
        #else
            // Suppress unused parameter warnings in release builds
            (void)format;
            (void)sizeof...(args);
        #endif
    }
}
