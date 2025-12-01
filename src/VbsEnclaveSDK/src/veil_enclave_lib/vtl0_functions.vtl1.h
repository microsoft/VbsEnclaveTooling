// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <string>
#include <array>

#include "wil/stl.h"
#include "utils.vtl1.h"

namespace veil::vtl1::implementation::vtl0_functions::callouts
{
    HRESULT internal_printf(_In_ const std::string& str);
    HRESULT internal_wprintf(_In_ const std::wstring& str);
}

namespace veil::vtl1::vtl0_functions
{
    namespace details
    {
        // printf_callout
        template <typename string_type>
        struct internal_printf_callout;

        template <>
        struct internal_printf_callout<std::string>
        {
            template <typename... Args>
            static void call(const std::string& str)
            {
                THROW_IF_FAILED(veil::vtl1::implementation::vtl0_functions::callouts::internal_printf(str));
            }
        };

        template <>
        struct internal_printf_callout<std::wstring>
        {
            template <typename... Args>
            static void call(const std::wstring& str)
            {
                THROW_IF_FAILED(veil::vtl1::implementation::vtl0_functions::callouts::internal_wprintf(str));
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
        inline void internal_debug_print_impl(const typename string_type::value_type* formatString, Ts&&... args)
        {
            if (veil::vtl1::is_enclave_full_debug_enabled())
            {
                auto str = details::format_string<string_type>::call(formatString, std::forward<Ts>(args)...);
                details::internal_printf_callout<string_type>::call(str);
            }
            else
            {
                UNREFERENCED_PARAMETER(formatString);
                UNREFERENCED_PARAMETER_PACK(Ts, args);
            }
        }
    }

    template <typename... Ts>
    inline void internal_debug_print(PCSTR formatString, Ts&&... args)
    {
        details::internal_debug_print_impl<std::string>(formatString, std::forward<Ts>(args)...);
    }

    template <typename... Ts>
    inline void internal_debug_print(PCWSTR formatString, Ts&&... args)
    {
        details::internal_debug_print_impl<std::wstring>(formatString, std::forward<Ts>(args)...);
    }
}
