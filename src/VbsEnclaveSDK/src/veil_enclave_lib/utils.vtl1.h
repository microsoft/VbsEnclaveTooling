// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <span>

#include <wil/resource.h>

#include <winenclaveapi.h>


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
