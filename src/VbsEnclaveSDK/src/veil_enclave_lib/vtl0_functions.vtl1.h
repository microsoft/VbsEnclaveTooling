#pragma once

#include <array>
#include <string>

#include "wil/stl.h"

#include "registered_callbacks.vtl1.h"

namespace veil::vtl1::vtl0_functions
{
    inline void* malloc(size_t size)
    {
        // Try get buffer from call context

        // Perform host allocation by making an ocall.
        //return oe_host_malloc(size);

        void* output;
        //auto fp_malloc = (LPENCLAVE_ROUTINE)implementation::get_callback(L"malloc");
        auto fp_malloc = (LPENCLAVE_ROUTINE)veil::vtl1::implementation::get_callback(veil::callback_id::malloc);
        THROW_IF_WIN32_BOOL_FALSE(CallEnclave((LPENCLAVE_ROUTINE)fp_malloc, reinterpret_cast<void*>(size), TRUE, reinterpret_cast<void**>(&output)));
        return output;
    }


    namespace details
    {
        template <typename T>
        struct string_traits;

        template <>
        struct string_traits<std::string>
        {
            static inline char nul_char = '\0';
            static inline veil::callback_id callback_id = veil::callback_id::printf;
        };

        template <>
        struct string_traits<std::wstring>
        {
            static inline wchar_t nul_char = L'\0';
            static inline veil::callback_id callback_id = veil::callback_id::wprintf;
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
                THROW_IF_FAILED(::StringCchPrintfA(outString, MAX_PATH, formatString, std::forward<Args>(args)...));
            }
        };

        template <>
        struct StringCchPrintf<std::wstring>
        {
            template <typename... Args>
            static void call(STRSAFE_LPWSTR outString, PCWSTR formatString, Args&&... args)
            {
                THROW_IF_FAILED(::StringCchPrintfW(outString, MAX_PATH, formatString, std::forward<Args>(args)...));
            }
        };

        // format string
        template <typename string_type>
        struct format_string
        {
            template <typename... Args>
            static string_type call(const typename string_type::value_type* formatString, Args&&... args)
            {
                std::array<typename string_type::value_type, MAX_PATH> outString;
                StringCchPrintf<string_type>::call(outString.data(), formatString, std::forward<Args>(args)...);
                return { outString.data() };
            }
        };

        // print string
        template <typename string_type, typename... Ts>
        inline void print_string_impl(const typename string_type::value_type* formatString, Ts&&... args)
        {
            auto str = details::format_string<string_type>::call(formatString, std::forward<Ts>(args)...);

            void* output{};

            size_t len = str.size();
            size_t cbBuffer = (len + 1) * sizeof(string_type::value_type);

            auto fp_malloc = (LPENCLAVE_ROUTINE)veil::vtl1::implementation::get_callback(veil::callback_id::malloc);
            THROW_IF_WIN32_BOOL_FALSE(CallEnclave((LPENCLAVE_ROUTINE)fp_malloc, reinterpret_cast<void*>(cbBuffer), TRUE, reinterpret_cast<void**>(&output)));

            void* allocation = veil::vtl1::vtl0_functions::malloc(cbBuffer);
            THROW_IF_NULL_ALLOC(allocation);

            auto buffer = reinterpret_cast<string_type::value_type*>(allocation);

            memcpy(buffer, str.c_str(), cbBuffer);
            buffer[len] = string_traits<string_type>::nul_char;

            auto funcPrintf = veil::vtl1::implementation::get_callback(string_traits<string_type>::callback_id);
            THROW_IF_WIN32_BOOL_FALSE(CallEnclave((LPENCLAVE_ROUTINE)funcPrintf, reinterpret_cast<void*>(buffer), TRUE, reinterpret_cast<void**>(&output)));
            THROW_IF_FAILED(pvoid_to_hr(output));
        }
    }

    template <typename... Ts>
    inline void print_string(PCSTR formatString, Ts&&... args)
    {
        details::print_string_impl<std::string>(formatString, std::forward<Ts>(args)...);
    }

    template <typename... Ts>
    inline void print_wstring(PCWSTR formatString, Ts&&... args)
    {
        details::print_string_impl<std::wstring>(formatString, std::forward<Ts>(args)...);
    }
}
