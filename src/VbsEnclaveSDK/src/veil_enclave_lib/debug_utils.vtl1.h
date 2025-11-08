// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "vtl0_functions.vtl1.h"
#include <string>

// Forward declarations and inline implementations for VTL0 functions namespace
namespace veil::vtl1::implementation::vtl0_functions::callouts
{
HRESULT wprintf(_In_ const std::wstring& str);
}

namespace veil::vtl1::vtl0_functions
{
    // Simple debug print function that calls the vtl0 callback directly
    // This avoids the template complexity and provides the symbol the debug utilities need
inline void debug_print(const wchar_t* str)
{
    if (veil::vtl1::is_enclave_full_debug_enabled())
    {
        // Call the VTL0 callback directly with the string
        THROW_IF_FAILED(veil::vtl1::implementation::vtl0_functions::callouts::wprintf(std::wstring(str)));
    }
}
}

namespace veil::vtl1::debug
{
    // Debug printing function that only outputs in debug mode
inline void debug_print(const wchar_t* str)
{
    #ifdef _VEIL_INTERNAL_DEBUG
    veil::vtl1::vtl0_functions::debug_print(str);
    #else
        // Suppress unused parameter warning in release builds
    (void)str;
    #endif
}

// Debug printing function for std::wstring that only outputs in debug mode
inline void debug_print(const std::wstring& str)
{
    #ifdef _VEIL_INTERNAL_DEBUG
    veil::vtl1::vtl0_functions::debug_print(str.c_str());
    #else
        // Suppress unused parameter warning in release builds
    (void)str;
    #endif
}

// Debug printing function for formatted strings that only outputs in debug mode
template<typename... Args>
inline void debug_printf(const wchar_t* format, Args&&... args)
{
    #ifdef _VEIL_INTERNAL_DEBUG
        // Use a buffer to format the string
    wchar_t buffer[1024];
    swprintf_s(buffer, format, std::forward<Args>(args)...);
    veil::vtl1::vtl0_functions::debug_print(buffer);
    #else
        // Suppress unused parameter warnings in release builds
    (void)format;
    (void)sizeof...(args);
    #endif
}
}
