#include "pch.h"

#include <array>
#include <stdexcept>

#include <enclave_interface.vtl1.h>
#include <memory.vtl1.h>
#include <threadpool.vtl1.h>

#include "sample_arguments.any.h"

/*
* Our exports: My app-enclave's exports
*/
ENCLAVE_FUNCTION MySaveScreenshotExport(_In_ PVOID params)
{
    (void)params;

    THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_WAS_LOCKED), !veil::vtl1::enclave_interface::is_unlocked());

    // ..code here..

    return 0;
}

/*
* Some sample code
*/

using namespace veil::vtl1::vtl0_functions;

namespace RunThreadpoolExamples
{

    void Test_Dont_WaitForAllTasksToFinish(_In_ PVOID params)
    {
        auto data = reinterpret_cast<sample::args::RunThreadpoolExample*>(params);

        print_wstring(L"Creating threadpool with '%d' threads...", data->threadCount);

        auto tasks = std::vector<veil::vtl1::future<void>>();

        std::atomic<bool> ranLastTask = false;

        // threadpool
        {
            auto threadpool = veil::vtl1::threadpool(data->threadCount, false);

            // Use up all the threads
            for (uint32_t i = 0; i < data->threadCount; i++)
            {
                auto task = threadpool.queue_task([=]()
                {
                    print_wstring(L"hello from task: %d", i);
                    veil::vtl1::sleep(500);
                });
                tasks.push_back(std::move(task));
            }

            auto task = threadpool.queue_task([&ranLastTask]()
            {
                ranLastTask = true;
                print_wstring(L"...you SHOULD NOT see this message...");
            });

            // Detach the future from the shared state so its destructor doesn't block on waiting forever (it's never scheduled)
            task.detach();

            print_wstring(L"Waiting for threadpool to destruct...");
        }

        if (ranLastTask)
        {
            print_wstring(L"ERROR: Threadpool destructed after all tasks finished.");
        }
        else
        {
            print_wstring(L"SUCCEESS: Threadpool destructed before all tasks finished.");
        }
    }

    void Test_Do_WaitForAllTasksToFinish(_In_ PVOID params)
    {
        auto data = reinterpret_cast<sample::args::RunThreadpoolExample*>(params);

        print_wstring(L"Creating threadpool with '%d' threads...", data->threadCount);

        auto tasks = std::vector<veil::vtl1::future<void>>();

        std::atomic<bool> ranLastTask = false;

        // threadpool
        {
            auto threadpool = veil::vtl1::threadpool(data->threadCount, true);

            // Use up all the threads
            for (uint32_t i = 0; i < data->threadCount; i++)
            {
                auto task = threadpool.queue_task([=]()
                {
                    print_wstring(L"hello from task: %d", i);
                    veil::vtl1::sleep(500);
                });
                tasks.push_back(std::move(task));
            }

            auto task = threadpool.queue_task([&ranLastTask]()
            {
                ranLastTask = true;
                print_wstring(L"...you SHOULD see this message...");
            });
            tasks.push_back(std::move(task));

            print_wstring(L"Waiting for threadpool to destruct...");
        }

        if (!ranLastTask)
        {
            print_wstring(L"ERROR: Threadpool destructed before all tasks finished.");
        }
        else
        {
            print_wstring(L"SUCCEESS: Threadpool destructed after all tasks finished.");
        }
    }

    void UsageExample(_In_ PVOID params)
    {
        auto data = reinterpret_cast<sample::args::RunThreadpoolExample*>(params);

        print_wstring(L"Creating threadpool with '%d' threads...", data->threadCount);

        auto threadpool = veil::vtl1::threadpool(data->threadCount, true);

        auto task_1 = threadpool.queue_task([=]()
        {
            veil::vtl1::sleep(500);
            print_wstring(L"hello from task 1");
        });

        auto task_2 = threadpool.queue_task([=]()
        {
            veil::vtl1::sleep(500);
            print_wstring(L"hello from task 2");
        });

        struct complex_struct
        {  
            std::wstring contents;
        };

        auto a_complex_task = threadpool.queue_task([=]()
        {
            veil::vtl1::sleep(500);
            print_wstring(L"hello from complex task");
            return complex_struct{ L"this is a complex struct!" };
        });

        print_wstring(L"Waiting for tasks...");

        task_1.get();
        task_2.get();
        auto a_complex_struct = a_complex_task.get();

        print_wstring(L"complex task returned a complex struct: %ls", a_complex_struct.contents.c_str());

        print_wstring(L"Waiting for threadpool to destruct...");
    }

    void UsageExceptionExample(_In_ PVOID params)
    {
        auto data = reinterpret_cast<sample::args::RunThreadpoolExample*>(params);

        print_wstring(L"Creating threadpool with '%d' threads...", data->threadCount);

        auto threadpool = veil::vtl1::threadpool(data->threadCount, true);

        auto task1 = threadpool.queue_task([=]()
        {
            volatile int x = 5;
            if (x == 5)
            {
                throw std::runtime_error("task1 threw this exception");
            }
        });

        auto task2 = threadpool.queue_task([=]()
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
            print_string("Caught exception from running task: %s", e.what());
        }

        try
        {
            task2.get();
        }
        catch (std::runtime_error e)
        {
            print_string("Caught exception from running task: %s", e.what());
        }

        print_wstring(L"Waiting for threadpool to destruct...");
    }
}

ENCLAVE_FUNCTION RunThreadpoolExample(_In_ PVOID params) try
{
#if 0
    print_string(L"TEST");
    RunThreadpoolExamples::Test_Dont_WaitForAllTasksToFinish(params);
    print_string(L"");

    print_string(L"TEST");
    RunThreadpoolExamples::Test_Do_WaitForAllTasksToFinish(params);
    print_string(L"");

    print_string(L"USAGE");
    RunThreadpoolExamples::UsageExample(params);
    print_string(L"");
#endif

    print_wstring(L"USAGE EXCEPTIONS");
    RunThreadpoolExamples::UsageExceptionExample(params);
    print_wstring(L"");

    RETURN_HR_AS_PVOID(S_OK);
}
catch (...)
{
    RETURN_HR_AS_PVOID(wil::ResultFromCaughtException());
}
