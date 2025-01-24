// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <functional>
#include <map>

#include "future.vtl1.h"
#include "memory.vtl1.h"
#include "object_table.vtl1.h"
#include "registered_callbacks.vtl1.h"
#include "utils.vtl1.h"
#include "vtl0_functions.vtl1.h"

#include "veil_arguments.any.h"

//
// TODO: SECURITY
// 
// Call-in and callback data/buffer memcpying, bounds-checks + TOCTOU
// safety is missing and waiting for the .edl tooling codegen work
// implemented & consumed.
//

/*

[Feature]
    Provides a taskpool to vtl1 code (veil::vtl1::taskpool) that queues tasks,
    and returns a future.  This is like std::async, but allows the user to
    specify how many threads are in the pool to limit the total number of
    concurrently running tasks.

    Allows exceptions to propagate on .get()-ing thread.

[Usage]

    void usage()
    {
        auto taskpool = veil::vtl1::taskpool{};

        auto task1 = taskpool.queue_task([]() {
            // Do work
        });

        auto task2 = taskpool.queue_task([]() {
            // Do work
            return 55;
        });

        auto task3 = taskpool.queue_task([]() {
            // Do work
            throw std::runtime_error("uh-oh");
        });

        task1.get();
        int x = task2.get();  // 55
        try {
            task3.get();
        } catch (...){
            //handle error
        }

[Implementation]

    This is a taskpool designed to be used in VTL1.  VTL1 cannot dynamically create threads
    or easily schedule work onto threads. To work around this limitation, a backing VTL0 thread
    will act as a conduit to get a task scheduled an available thread in VTL1.

    Task scheduling flow mechanics:
        0. VTL1 app enclave consumer calls taskpool's queue_task(lambda)
        1. VTL1 taskpool stores the task (lambda) /w a task id
        2. VTL1 calls out to VTL0, passing the task id
        3. VTL0 switches to an available thread, calls into enclave (CallEnclave), passing the task id
        4. VTL1 is now running on a different thread and has the task id(!!)
        5. VTL1 retrieves the task (lambda) using the task id and runs the task's lambda

[Behavior]

    Blocking destructor:

    Letting a taskpool fall out of scope will block until the taskpool's queue is
    cleared (i.e. until all tasks are done or unscheduled).

*/

// fwd decls
namespace veil::vtl1
{
    struct taskpool;
}

// call ins
namespace veil::vtl1::implementation::exports
{
    HRESULT taskpool_run_task(_Inout_ veil::any::implementation::args::taskpool_run_task* params);
}

// object table entries
namespace veil::vtl1::implementation
{
    weak_object_table<keepalive_object_proxy<taskpool>>& get_taskpool_object_table();
}

// impl
namespace veil::vtl1
{
    struct taskpool
    {
    public:

        //
        // Note about thread count:
        // 
        //   The threadCount should be at most,
        // 
        //      <thread count> = [IMAGE_ENCLAVE_CONFIG.NumberOfThreads - 1]
        // 
        //   so the enclave always has a theoretical thread of execution available.  It's not strictly
        //   necessary, because VLT0<->VTL1 threads are not 1:1. If you have too many logical threads
        //   in the taskpool, it won't deadlock (just blocks until a previous task finishes).
        // 
        //   i.e. It's not fatal, merely wasteful, to park extra VTL0 threads.
        //

        taskpool(uint32_t threadCount, bool mustFinishAllQueuedTasks = true)
            : m_keepaliveMechanism(*this)
        {
            // Store this taskpool (weakly) into a global table of taskpools (and get a unique id)
            m_objectTableEntryId = veil::vtl1::implementation::get_taskpool_object_table().store(m_keepaliveMechanism.get_weak());

            void* enclave = veil::vtl1::enclave_information().BaseAddress;

            // Call out to VTL0 to create the backing threads (TODO:NOT SAFE UNTIL TOOLING WORK COMPLETE)
            auto makeTaskpoolArgs = veil::vtl1::memory::allocate_vtl0<veil::any::implementation::args::taskpool_make>();

            void* output{};
            auto makeTaskpool = veil::vtl1::implementation::get_callback(veil::implementation::callback_id::taskpool_make);
            makeTaskpoolArgs->enclave = enclave;
            makeTaskpoolArgs->taskpoolInstanceVtl1 = static_cast<uint64_t>(m_objectTableEntryId);
            makeTaskpoolArgs->threadCount = threadCount;
            makeTaskpoolArgs->mustFinishAllQueuedTasks = mustFinishAllQueuedTasks;
            THROW_IF_WIN32_BOOL_FALSE(::CallEnclave(makeTaskpool, reinterpret_cast<void*>(makeTaskpoolArgs.get()), TRUE, reinterpret_cast<void**>(&output)));
            THROW_IF_FAILED(pvoid_to_hr(output));

            m_taskpoolInstanceVtl0 = makeTaskpoolArgs->taskpoolInstanceVtl0;
        }

        // Delete copy
        taskpool(const taskpool&) = delete;
        taskpool& operator=(const taskpool&) = delete;

        // Allow move
        taskpool(taskpool&& other) = default;
        taskpool& operator=(taskpool&& other) = default;

        ~taskpool()
        {
            auto deleteTaskpoolArgs = veil::vtl1::memory::allocate_vtl0<veil::any::implementation::args::taskpool_delete>();
            deleteTaskpoolArgs->taskpoolInstanceVtl0 = m_taskpoolInstanceVtl0;

            // Call out to VTL0 to delete the backing threads (TODO:NOT SAFE UNTIL TOOLING WORK COMPLETE)
            void* output{};
            auto deleteTaskpool = veil::vtl1::implementation::get_callback(veil::implementation::callback_id::taskpool_delete);
            deleteTaskpoolArgs->taskpoolInstanceVtl0 = m_taskpoolInstanceVtl0;
            THROW_IF_WIN32_BOOL_FALSE(::CallEnclave(deleteTaskpool, reinterpret_cast<void*>(deleteTaskpoolArgs.get()), TRUE, reinterpret_cast<void**>(&output)));
            THROW_IF_FAILED(pvoid_to_hr(output));

            // Erase weak reference from weak object table so nobody else can run tasks
            veil::vtl1::implementation::get_taskpool_object_table().erase(m_objectTableEntryId);

            // Stay alive if someone is holding a strong reference to the keepalive mechanism's "keepalive_object_proxy"
            //   (strong-reference to the weak-entry in the weak object table).
            //
            // Note: Calling explicitly here for clarity, but m_keepalive would have called it anyway in dtor.
            m_keepaliveMechanism.release_keepalive_and_block();
        }

        template <typename F>
        [[nodiscard]] auto queue_task(F&& f) -> veil::vtl1::future<decltype(f())>
        {
            using return_type = decltype(f());

            // Make a promise + future pair.
            //  - The future will be given to caller for waiting-on/getting the task result (or exception).
            //  - The promise will be given to the task lambda to set task result (or exception).
            auto promise = std::make_shared<veil::vtl1::promise<return_type>>();
            auto fut = promise->get_future();

            auto func = [f = std::move(f), p = std::move(promise)]()
            {
                if constexpr (std::is_same_v<return_type, void>)
                {
                    // Handle void return type
                    try
                    {
                        f();
                        p->set_value();
                    }
                    catch (...)
                    {
                        p->set_exception(std::current_exception());
                    }
                }
                else
                {
                    // Handle non-void return type
                    try
                    {
                        auto value = f();
                        p->set_value(std::move(value));
                    }
                    catch (...)
                    {
                        p->set_exception(std::current_exception());
                    }
                }
            };

            // Store the task in an object table, getting an id we can share with VTL0
            auto taskId = m_tasks.store(std::move(func));

            auto taskHandleArgs = veil::vtl1::memory::allocate_vtl0<veil::any::implementation::args::taskpool_schedule_task>();
            taskHandleArgs->taskpoolInstanceVtl0 = m_taskpoolInstanceVtl0;
            taskHandleArgs->taskId = taskId;

            // Call out to VTL0 to get the task scheduled (into the VTL0 std::deque instance) so it can eventually be scheduled on a VTL0 backing thread.  (TODO:NOT SAFE UNTIL TOOLING WORK COMPLETE)
            void* output{};
            auto vtl0_scheduleTask_callback = veil::vtl1::implementation::get_callback(veil::implementation::callback_id::taskpool_schedule_task);
            THROW_IF_WIN32_BOOL_FALSE(::CallEnclave(vtl0_scheduleTask_callback, reinterpret_cast<void*>(taskHandleArgs.get()), TRUE, reinterpret_cast<void**>(&output)));
            THROW_IF_FAILED(pvoid_to_hr(output));

            return fut;
        }

        void run_task(UINT64 taskHandle)
        {
            // Take the task out of our task table
            auto task = m_tasks.try_take(taskHandle);
            if (!task)
            {
                THROW_WIN32_MSG(ERROR_INVALID_INDEX, "Task handle doesn't exist: %d", static_cast<int>(taskHandle));
            }

            auto& task_lambda = task.value();

            // Finally run the task, which is a std::function<void()> that,
            //  1. Runs the captured user-provided lambda
            //  2. Runs the promise setter (so the user's future is live)
            task_lambda();

            // The task, std::function<void()>, is freed...
        }

    private:
        // Task objects (but the actual queue order is managed in vtl0)
        veil::vtl1::unique_object_table<std::function<void()>> m_tasks;

        // Backing threads in vtl0
        void* m_taskpoolInstanceVtl0{};

        // Required for secure lifetime management and to avoid passing contexts (void*) pointers to vtl0
        veil::vtl1::keepalive_mechanism<taskpool> m_keepaliveMechanism;
        size_t m_objectTableEntryId{};
    };
}


