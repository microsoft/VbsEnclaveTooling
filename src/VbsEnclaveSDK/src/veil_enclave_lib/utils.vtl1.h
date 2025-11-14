// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <span>
#include <string>
#include <string_view>

#include <wil/resource.h>

#include <winenclaveapi.h>

#define VEIL_THROW(hr) \
    { \
        volatile int x = 1; \
        if (x == 1) \
        { \
            THROW_HR(hr); \
        } \
    } \

#define UNREFERENCED_PARAMETER_PACK(Ts, x) veil::vtl1::implementation::details::ignore_parameter_pack(std::forward<Ts>(x)...)

namespace veil::vtl1::implementation
{
    namespace details
    {
        template <typename... Ts>
        constexpr void ignore_parameter_pack(Ts&&... args)
        {
            auto ignored = {(std::forward<Ts&>(args))...};
            (void)ignored;
        }

        template <>
        constexpr void ignore_parameter_pack<>()
        {
        }
    }
}

namespace veil::vtl1
{
    constexpr bool buffers_are_equal(std::span<const uint8_t> a, std::span<const uint8_t> b) noexcept
    {
        if (a.size() != b.size())
        {
            return false;
        }
        return memcmp(a.data(), b.data(), a.size()) == 0;
    }

    inline std::vector<uint8_t> to_data(std::wstring_view str)
    {
        auto x = std::span<uint8_t const>((const uint8_t*)str.data(), str.size() * sizeof(std::wstring_view::traits_type::char_type));
        auto vec = std::vector<uint8_t>();
        vec.assign(x.begin(), x.end());
        return vec;
    }

    inline std::span<uint8_t const> as_data_span(std::wstring_view str)
    {
        return {reinterpret_cast<const uint8_t*>(str.data()), str.size() * sizeof(std::wstring_view::traits_type::char_type)};
    }

    inline std::wstring to_wstring(std::span<const uint8_t> buffer)
    {
        return std::wstring((wchar_t*)buffer.data(), buffer.size() / sizeof(wchar_t));
    }

    inline void copy_span(std::span<uint8_t const> source, std::span<uint8_t> destination)
    {
        THROW_WIN32_IF(ERROR_INCORRECT_SIZE, destination.size() != source.size());
        std::copy(source.begin(), source.end(), destination.begin());
    }

    // We only need narrow_cast from Microsoft GSL, not the entire dependency. So, we reimplement it here
    // to avoid pulling in all of GSL.
    // See narrow_cast implementation: https://github.com/microsoft/GSL/blob/7e0943d20d3082b4f350a7e0c3088d2388e934de/include/gsl/util#L129
    template <class T, class U>
    constexpr T narrow_cast(U&& u) noexcept
    {
        return static_cast<T>(std::forward<U>(u));
    }
}

namespace veil::vtl1
{
    inline ENCLAVE_INFORMATION& enclave_information()
    {
        static ENCLAVE_INFORMATION enclaveInformation = []()
        {
            ENCLAVE_INFORMATION info;
            THROW_IF_FAILED(::EnclaveGetEnclaveInformation(sizeof(ENCLAVE_INFORMATION), &info));
            return info;
        }();
        return enclaveInformation;
    }

    inline bool is_enclave_full_debug_enabled()
    {
        static bool fullDebugEnabled = [] ()
        {
            auto& identity = enclave_information().Identity;
            return WI_IsFlagSet(identity.Flags, ENCLAVE_FLAG_FULL_DEBUG_ENABLED);
        }();
        return fullDebugEnabled;
    }

    inline void sleep(DWORD milliseconds)
    {
        LARGE_INTEGER frequency;
        LARGE_INTEGER startTime;
        LARGE_INTEGER endTime;

        // Retrieve the frequency of the high-resolution performance counter
        if (!QueryPerformanceFrequency(&frequency))
        {
            return;
        }

        // Calculate the target time in performance counter ticks
        LONGLONG targetTicks = (frequency.QuadPart * milliseconds) / 1000;

        // Record the starting time
        if (!QueryPerformanceCounter(&startTime))
        {
            return;
        }

        // Use a condition variable to implement precise sleep
        wil::srwlock srwlock;
        auto lock = srwlock.lock_exclusive();
        wil::condition_variable cv;

        while (true)
        {
            // Check the current time
            if (!QueryPerformanceCounter(&endTime))
            {
                return;
            }

            LONGLONG elapsedTicks = endTime.QuadPart - startTime.QuadPart;

            // Exit loop if the target time has been reached
            if (elapsedTicks >= targetTicks)
            {
                break;
            }

            // Calculate the remaining time in milliseconds
            LONGLONG remainingTicks = targetTicks - elapsedTicks;
            DWORD remainingMilliseconds = static_cast<DWORD>((remainingTicks * 1000) / frequency.QuadPart);

            // Wait using condition_variable with a short timeout to minimize busy-waiting
            cv.wait_for(lock, remainingMilliseconds);
        }
    }
}

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
