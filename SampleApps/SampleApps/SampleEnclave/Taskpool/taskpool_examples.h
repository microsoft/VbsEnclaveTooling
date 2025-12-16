// Copyright (c) Microsoft Corporation.
//

#pragma once

#include <cstdint>

// Taskpool example functions
namespace RunTaskpoolExamples
{
    void Test_Dont_WaitForAllTasksToFinish(uint32_t threadCount);
    void Test_Do_WaitForAllTasksToFinish(uint32_t threadCount);
    void Test_Cancellation(uint32_t threadCount);
    void UsageExample(uint32_t threadCount);
    void UsageExceptionExample(uint32_t threadCount);
}

// Public API function for taskpool operations
namespace VbsEnclave::Trusted::Implementation
{
    HRESULT RunTaskpoolExample(_In_ const std::uint32_t threadCount);
}
