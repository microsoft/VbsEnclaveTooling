// <copyright placeholder>

#pragma once

#include <span>
#include <vector>

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
    inline void sleep(DWORD milliseconds) noexcept
    {
        CONDITION_VARIABLE cv;
        SRWLOCK lock;
        InitializeConditionVariable(&cv);
        InitializeSRWLock(&lock);

        AcquireSRWLockExclusive(&lock);
        SleepConditionVariableSRW(&cv, &lock, milliseconds, 0);
        ReleaseSRWLockExclusive(&lock);
    }
}
