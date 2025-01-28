// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "pch.h"

#include <array>
#include <stdexcept>

#include <enclave_interface.vtl1.h>
#include <taskpool.vtl1.h>
#include <vtl0_functions.vtl1.h>

#include "sample_arguments.any.h"

//
// My app exports: My app-enclave's exports
//
ENCLAVE_FUNCTION MySaveScreenshotExport(_In_ PVOID params)
{
    (void)params;

    // ..code here..

    return 0;
}

//
// Some sample code
//

namespace RunTaskpoolExamples
{

    void Test_Dont_WaitForAllTasksToFinish(_In_ sample::args::RunTaskpoolExample* data)
    {
        using namespace veil::vtl1::vtl0_functions;

        debug_print(L"Creating taskpool with '%d' threads...", data->threadCount);

        auto tasks = std::vector<veil::vtl1::future<void>>();

        std::atomic<bool> ranLastTask = false;

        // taskpool
        {
            auto taskpool = veil::vtl1::taskpool(data->threadCount, false);

            // Use up all the threads
            for (uint32_t i = 0; i < data->threadCount; i++)
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

    void Test_Do_WaitForAllTasksToFinish(_In_ sample::args::RunTaskpoolExample* data)
    {
        using namespace veil::vtl1::vtl0_functions;

        debug_print(L"Creating taskpool with '%d' threads...", data->threadCount);

        auto tasks = std::vector<veil::vtl1::future<void>>();

        std::atomic<bool> ranLastTask = false;

        // taskpool
        {
            auto taskpool = veil::vtl1::taskpool(data->threadCount, true);

            // Use up all the threads
            for (uint32_t i = 0; i < data->threadCount; i++)
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

    void Test_Cancellation(_In_ sample::args::RunTaskpoolExample* data)
    {
        using namespace veil::vtl1::vtl0_functions;

        debug_print(L"Creating taskpool with '%d' threads...", data->threadCount);

        auto tasks = std::vector<veil::vtl1::future<void>>();

        std::atomic<bool> ranLastTask = false;

        // taskpool
        {
            auto taskpool = veil::vtl1::taskpool(data->threadCount, true);

            // Use up all the threads
            for (uint32_t i = 0; i < data->threadCount; i++)
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

    void UsageExample(_In_ sample::args::RunTaskpoolExample* data)
    {
        using namespace veil::vtl1::vtl0_functions;

        debug_print(L"Creating taskpool with '%d' threads...", data->threadCount);

        auto taskpool = veil::vtl1::taskpool(data->threadCount, true);

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

    void UsageExceptionExample(_In_ sample::args::RunTaskpoolExample* data)
    {
        using namespace veil::vtl1::vtl0_functions;

        debug_print(L"Creating taskpool with '%d' threads...", data->threadCount);

        auto taskpool = veil::vtl1::taskpool(data->threadCount, true);

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

void RunTaskpoolExampleImpl(_In_ sample::args::RunTaskpoolExample* data)
{
    using namespace veil::vtl1::vtl0_functions;

    debug_print(L"TEST: Taskpool destruction, don't wait for all tasks to finish");
    RunTaskpoolExamples::Test_Dont_WaitForAllTasksToFinish(data);
    debug_print(L"");

    debug_print(L"TEST: Taskpool destruction, wait for all tasks to finish");
    RunTaskpoolExamples::Test_Do_WaitForAllTasksToFinish(data);
    debug_print(L"");

    debug_print(L"TEST: Taskpool cancellation");
    RunTaskpoolExamples::Test_Cancellation(data);
    debug_print(L"");

    debug_print(L"USAGE");
    RunTaskpoolExamples::UsageExample(data);
    debug_print(L"");

    debug_print(L"USAGE EXCEPTIONS");
    RunTaskpoolExamples::UsageExceptionExample(data);
    debug_print(L"");
}

ENCLAVE_FUNCTION RunTaskpoolExample(_In_ PVOID pv) noexcept try
{
    // TODO: Use tooling codegen to create your exports, or manually use the
    // vtl0_ptr secure pointers.
    // RunTaskpoolExampleImpl(vtl0_ptr<RunTaslpoolExampleArgs>(pv));
    auto data = reinterpret_cast<sample::args::RunTaskpoolExample*>(pv);
    RunTaskpoolExampleImpl(data);
    return nullptr;
}
catch (...)
{
    LOG_CAUGHT_EXCEPTION();
    RETURN_HR_AS_PVOID(wil::ResultFromCaughtException());
}
