// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <string>
#include <array>

#include "wil/stl.h"
#include "utils.vtl1.h"

namespace veil::vtl1::implementation::vtl0_functions::callouts
{
    HRESULT printf(_In_ const std::string& str);
    HRESULT wprintf(_In_ const std::wstring& str);
}

namespace veil::vtl1::vtl0_functions
{
    namespace details
    {
        // printf_callout
        template <typename string_type>
        struct printf_callout;

        template <>
        struct printf_callout<std::string>
        {
            template <typename... Args>
            static void call(const std::string& str)
            {
                THROW_IF_FAILED(veil::vtl1::implementation::vtl0_functions::callouts::printf(str));
            }
        };

        template <>
        struct printf_callout<std::wstring>
        {
            template <typename... Args>
            static void call(const std::wstring& str)
            {
                THROW_IF_FAILED(veil::vtl1::implementation::vtl0_functions::callouts::wprintf(str));
            }
        };

        // StringCchPrintf
        template <typename string_type>
        struct StringCchPrintf;

        template <>
        struct StringCchPrintf<std::string>
        {
            template <typename... Args>
            static void call(STRSAFE_LPSTR outString, PCSTR formatString, Args&&... args)
            {
                THROW_IF_FAILED(::StringCchPrintfA(outString, 1000, formatString, std::forward<Args>(args)...));
            }
        };

        template <>
        struct StringCchPrintf<std::wstring>
        {
            template <typename... Args>
            static void call(STRSAFE_LPWSTR outString, PCWSTR formatString, Args&&... args)
            {
                THROW_IF_FAILED(::StringCchPrintfW(outString, 1000, formatString, std::forward<Args>(args)...));
            }
        };

        // format string
        template <typename string_type>
        struct format_string
        {
            template <typename... Args>
            static string_type call(const typename string_type::value_type* formatString, Args&&... args)
            {
                std::array<typename string_type::value_type, 1000> outString;
                StringCchPrintf<string_type>::call(outString.data(), formatString, std::forward<Args>(args)...);
                return { outString.data() };
            }
        };

        // debug print string
        template <typename string_type, typename... Ts>
        inline void debug_print_impl(const typename string_type::value_type* formatString, Ts&&... args)
        {
            if (veil::vtl1::is_enclave_full_debug_enabled())
            {
                auto str = details::format_string<string_type>::call(formatString, std::forward<Ts>(args)...);
                details::printf_callout<string_type>::call(str);
            }
            else
            {
                UNREFERENCED_PARAMETER(formatString);
                UNREFERENCED_PARAMETER_PACK(Ts, args);
            }
        }
    }

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

    template <typename... Ts>
    inline void debug_print(PCSTR formatString, Ts&&... args)
    {
        details::debug_print_impl<std::string>(formatString, std::forward<Ts>(args)...);
    }

    template <typename... Ts>
    inline void debug_print(PCWSTR formatString, Ts&&... args)
    {
        details::debug_print_impl<std::wstring>(formatString, std::forward<Ts>(args)...);
    }
}

// High-level debug interface that uses _VEIL_INTERNAL_DEBUG compile-time flag
namespace veil::vtl1::debug
{
    // Debug printing function that only outputs when _VEIL_INTERNAL_DEBUG is defined
    inline void debug_print(const wchar_t* str)
    {
        #ifdef _VEIL_INTERNAL_DEBUG
            veil::vtl1::vtl0_functions::debug_print(str);
        #else
            // Suppress unused parameter warning in release builds
            (void)str;
        #endif
    }

    // Debug printing function for std::wstring that only outputs when _VEIL_INTERNAL_DEBUG is defined
    inline void debug_print(const std::wstring& str)
    {
        #ifdef _VEIL_INTERNAL_DEBUG
            veil::vtl1::vtl0_functions::debug_print(str.c_str());
        #else
            // Suppress unused parameter warning in release builds
            (void)str;
        #endif
    }

    // Debug printing function for formatted strings that only outputs when _VEIL_INTERNAL_DEBUG is defined
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
