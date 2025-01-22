// <copyright placeholder>

#pragma once

#include <array>
#include <string>

#include "wil/stl.h"

#include "registered_callbacks.vtl1.h"

namespace veil::vtl1::vtl0_functions
{
    // todo: stand-in type until tooling+marshalling code is online
    //  <This is ** not ** a smart pointer>
    struct VTL0_PTR
    {
        VTL0_PTR(void* memory)
            : m_dangerous(memory)
        {
        }

        void* m_dangerous;
    };

    inline VTL0_PTR malloc(size_t size)
    {
        // TODO:Branden security-todo
        // 
        // Ensure malloc implements all relevant vulnerabilities handled by OpenEnclave.
        // i.e. 8-byte alignment to prevent 'Processor MMIO Stale Data Vulnerabilities'
        // that propagate stale data into core fill buffers.  It may be that they don't
        // apply to software enclaves.
        // 
        // See here:
        //  https://github.com/openenclave/openenclave/blob/master/docs/GettingStartedDocs/SecurityGuideForMMIOVulnerabilities.md
        //  https://docs.kernel.org/admin-guide/hw-vuln/processor_mmio_stale_data.html
        //  https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/technical-documentation/processor-mmio-stale-data-vulnerabilities.html

        void* output;
        auto malloc = veil::vtl1::implementation::get_callback(veil::implementation::callback_id::malloc);
        THROW_IF_WIN32_BOOL_FALSE(::CallEnclave(malloc, reinterpret_cast<void*>(size), TRUE, reinterpret_cast<void**>(&output)));
        return { output };
    }

    inline void free(void* memory) noexcept
    {
        void* output;
        auto free = veil::vtl1::implementation::get_callback(veil::implementation::callback_id::free);
        LOG_IF_WIN32_BOOL_FALSE(::CallEnclave(free, reinterpret_cast<void*>(memory), TRUE, reinterpret_cast<void**>(&output)));
    }

    namespace details
    {
        template <typename T>
        struct string_traits;

        template <>
        struct string_traits<std::string>
        {
            static inline char nul_char = '\0';
            static inline veil::implementation::callback_id callback_id = veil::implementation::callback_id::printf;
        };

        template <>
        struct string_traits<std::wstring>
        {
            static inline wchar_t nul_char = L'\0';
            static inline veil::implementation::callback_id callback_id = veil::implementation::callback_id::wprintf;
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

            auto allocation = veil::vtl1::vtl0_functions::malloc(cbBuffer);
            THROW_IF_NULL_ALLOC(allocation.m_dangerous);

            auto buffer = reinterpret_cast<string_type::value_type*>(allocation.m_dangerous);

            memcpy(buffer, str.c_str(), cbBuffer);
            buffer[len] = string_traits<string_type>::nul_char;

            auto funcPrintf = veil::vtl1::implementation::get_callback(string_traits<string_type>::callback_id);
            THROW_IF_WIN32_BOOL_FALSE(::CallEnclave(funcPrintf, reinterpret_cast<void*>(buffer), TRUE, reinterpret_cast<void**>(&output)));
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
