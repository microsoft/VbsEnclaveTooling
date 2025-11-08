// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <string>
#include <iostream>

namespace veil::vtl0::debug
{
    // Debug printing function that only outputs in debug mode
inline void WDebugPrint(const std::wstring& str)
{
    #ifdef _VEIL_INTERNAL_DEBUG
    std::wcout << str << std::endl;
    #endif
}

// Debug printing function for narrow strings
inline void DebugPrint(const std::string& str)
{
    #ifdef _VEIL_INTERNAL_DEBUG
    std::cout << str << std::endl;
    #endif
}
}
