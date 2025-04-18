// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "pch.h"

#include <taskpool.vtl1.h>
#include <vtl0_functions.vtl1.h>

#include <VbsEnclave\Enclave\Implementations.h>

//
// Some sample code
//

namespace RunTaskpoolExamples
{

    void Test_Dont_WaitForAllTasksToFinish(uint32_t threadCount)
    {
        using namespace veil::vtl1::vtl0_functions;

        debug_print(L"Creating taskpool with '%d' threads...", threadCount);

        auto tasks = std::vector<veil::vtl1::future<void>>();

        std::atomic<bool> ranLastTask = false;

        // taskpool
        {
            auto taskpool = veil::vtl1::taskpool(threadCount, false);

            // Use up all the threads
            for (uint32_t i = 0; i < threadCount; i++)
            {
                auto task = taskpool.queue_task([=]()
                {
                    debug_print(L"hello from task: %d", i);
                    veil::vtl1::sleep(500);
                });
                tasks.push_back(std::move(task));
            }

            auto task = taskpool.queue_task([&ranLastTask]()
            {
                ranLastTask = true;
                debug_print(L"...you SHOULD NOT see this message...");
            });

            // Detach the future from the shared state so its destructor doesn't block on waiting forever (it's never scheduled)
            task.detach();

            debug_print(L"Waiting for taskpool to destruct...");
        }

        if (ranLastTask)
        {
            debug_print(L"ERROR: Taskpool destructed after all tasks finished.");
        }
        else
        {
            debug_print(L"SUCCESS: Taskpool destructed before all tasks finished.");
        }

        // We must detach all unfinished tasks that still exist after the lifetime of the taskpool.
        // These tasks were never queued, so their destructors will block forever.
        for (auto& task : tasks)
        {
            task.detach();
        }
    }

    void Test_Do_WaitForAllTasksToFinish(uint32_t threadCount)
    {
        using namespace veil::vtl1::vtl0_functions;

        debug_print(L"Creating taskpool with '%d' threads...", threadCount);

        auto tasks = std::vector<veil::vtl1::future<void>>();

        std::atomic<bool> ranLastTask = false;

        // taskpool
        {
            auto taskpool = veil::vtl1::taskpool(threadCount, true);

            // Use up all the threads
            for (uint32_t i = 0; i < threadCount; i++)
            {
                auto task = taskpool.queue_task([=]()
                {
                    debug_print(L"hello from task: %d", i);
                    veil::vtl1::sleep(500);
                });
                tasks.push_back(std::move(task));
            }

            auto task = taskpool.queue_task([&ranLastTask]()
            {
                ranLastTask = true;
                debug_print(L"...you SHOULD see this message...");
            });
            tasks.push_back(std::move(task));

            debug_print(L"Waiting for taskpool to destruct...");
        }

        if (!ranLastTask)
        {
            debug_print(L"ERROR: Taskpool destructed before all tasks finished.");
        }
        else
        {
            debug_print(L"SUCCESS: Taskpool destructed after all tasks finished.");
        }
    }

    void Test_Cancellation(uint32_t threadCount)
    {
        using namespace veil::vtl1::vtl0_functions;

        debug_print(L"Creating taskpool with '%d' threads...", threadCount);

        auto tasks = std::vector<veil::vtl1::future<void>>();

        std::atomic<bool> ranLastTask = false;

        // taskpool
        {
            auto taskpool = veil::vtl1::taskpool(threadCount, true);

            // Use up all the threads
            for (uint32_t i = 0; i < threadCount; i++)
            {
                auto task = taskpool.queue_task([=]()
                {
                    debug_print(L"hello from task: %d", i);
                    veil::vtl1::sleep(500);
                });
                task.detach();
            }

            auto task = taskpool.queue_task([&ranLastTask]()
            {
                ranLastTask = true;
                debug_print(L"...you SHOULD NOT see this message...");
            });
            task.detach();

            taskpool.cancel_queued_tasks();

            debug_print(L"Waiting for taskpool to destruct...");
        }

        if (ranLastTask)
        {
            debug_print(L"ERROR: Taskpool destructed after all tasks finished.");
        }
        else
        {
            debug_print(L"SUCCESS: Taskpool destructed before all tasks finished.");
        }
    }

    void UsageExample(uint32_t threadCount)
    {
        using namespace veil::vtl1::vtl0_functions;

        debug_print(L"Creating taskpool with '%d' threads...", threadCount);

        auto taskpool = veil::vtl1::taskpool(threadCount, true);

        auto task_1 = taskpool.queue_task([=]()
        {
            veil::vtl1::sleep(500);
            debug_print(L"hello from task 1");
        });

        auto task_2 = taskpool.queue_task([=]()
        {
            veil::vtl1::sleep(500);
            debug_print(L"hello from task 2");
        });

        struct complex_struct
        {  
            std::wstring contents;
        };

        auto a_complex_task = taskpool.queue_task([=]()
        {
            veil::vtl1::sleep(500);
            debug_print(L"hello from complex task");
            return complex_struct{ L"this is a complex struct!" };
        });

        debug_print(L"Waiting for tasks...");

        task_1.get();
        task_2.get();
        auto a_complex_struct = a_complex_task.get();

        debug_print(L"complex task returned a complex struct: %ls", a_complex_struct.contents.c_str());

        debug_print(L"Waiting for taskpool to destruct...");
    }

    void UsageExceptionExample(uint32_t threadCount)
    {
        using namespace veil::vtl1::vtl0_functions;

        debug_print(L"Creating taskpool with '%d' threads...", threadCount);

        auto taskpool = veil::vtl1::taskpool(threadCount, true);

        auto task1 = taskpool.queue_task([=]()
        {
            volatile int x = 5;
            if (x == 5)
            {
                throw std::runtime_error("task1 threw this exception");
            }
        });

        auto task2 = taskpool.queue_task([=]()
        {
            volatile int x = 5;
            if (x == 5)
            {
                throw std::runtime_error("task2 threw this exception");
            }
            return 1234;
        });

        try
        {
            task1.get();
        }
        catch (std::runtime_error e)
        {
            debug_print("Caught exception from running task: %s", e.what());
        }

        try
        {
            task2.get();
        }
        catch (std::runtime_error e)
        {
            debug_print("Caught exception from running task: %s", e.what());
        }

        debug_print(L"Waiting for taskpool to destruct...");
    }
}

//
// Exports
//
void sample_abi::VTL1_Declarations::RunTaskpoolExample(_In_ const std::uint32_t thread_count)
{
    using namespace veil::vtl1::vtl0_functions;

    debug_print(L"TEST: Taskpool destruction, don't wait for all tasks to finish");
    RunTaskpoolExamples::Test_Dont_WaitForAllTasksToFinish(thread_count);
    debug_print(L"");

    debug_print(L"TEST: Taskpool destruction, wait for all tasks to finish");
    RunTaskpoolExamples::Test_Do_WaitForAllTasksToFinish(thread_count);
    debug_print(L"");

    debug_print(L"TEST: Taskpool cancellation");
    RunTaskpoolExamples::Test_Cancellation(thread_count);
    debug_print(L"");

    debug_print(L"USAGE");
    RunTaskpoolExamples::UsageExample(thread_count);
    debug_print(L"");

    debug_print(L"USAGE EXCEPTIONS");
    RunTaskpoolExamples::UsageExceptionExample(thread_count);
    debug_print(L"");
}
