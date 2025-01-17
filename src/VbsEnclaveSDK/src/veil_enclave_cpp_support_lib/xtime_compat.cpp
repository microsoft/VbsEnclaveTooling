// © Microsoft Corporation. All rights reserved.

#include "pch.h"

#include <atomic>
static bool xticks_initialized = false;

LARGE_INTEGER g_initialCounter;
LARGE_INTEGER g_frequency;

void InitializeTickCount64()
{
    // Get the initial performance counter value
    QueryPerformanceCounter(&g_initialCounter);
    // Get the frequency of the performance counter
    QueryPerformanceFrequency(&g_frequency);
}

// xtime.cpp
/*
long long _Xtime_get_ticks()
{
    if (xticks_initialized == false)
    {
        InitializeTickCount64();
        xticks_initialized = true;
    }

    LARGE_INTEGER currentCounter;
    QueryPerformanceCounter(&currentCounter);

    // Calculate the difference between the current counter and the initial counter
    LONGLONG counterDifference = currentCounter.QuadPart - g_initialCounter.QuadPart;

    // Convert the counter difference to milliseconds
    ULONGLONG ticks = (counterDifference * 1000) / g_frequency.QuadPart;

    return ticks;
}

long long __cdecl _Query_perf_counter()
{ // get current value of performance counter
    LARGE_INTEGER li;
    QueryPerformanceCounter(&li); // always succeeds
    return li.QuadPart;
}

long long __cdecl _Query_perf_frequency()
{ // get frequency of performance counter
    static std::atomic<long long> freq_cached{ 0 };
    long long freq = freq_cached.load(std::memory_order_relaxed);
    if (freq == 0)
    {
        LARGE_INTEGER li;
        QueryPerformanceFrequency(&li); // always succeeds
        freq = li.QuadPart;             // doesn't change after system boot
        freq_cached.store(freq, std::memory_order_relaxed);
    }
    return freq;
}
*/
