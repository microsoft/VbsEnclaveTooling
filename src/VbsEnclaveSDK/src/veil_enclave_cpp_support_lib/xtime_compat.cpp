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
