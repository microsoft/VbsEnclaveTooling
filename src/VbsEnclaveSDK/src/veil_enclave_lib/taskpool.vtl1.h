#pragma once

#include <functional>
#include <map>

#include "future.vtl1.h"
#include "object_table.vtl1.h"
#include "registered_callbacks.vtl1.h"
#include "vtl0_functions.vtl1.h"

#include "veil_arguments.any.h"

/*
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
        0. VTL1 app enclave consumer calls taskpool's add_task(lambda)
        1. VTL1 taskpool stores the task (lambda) /w a task id
        2. VTL1 calls out to VTL0, passing the task id
        3. VTL0 switches to an available thread, calls into enclave (CallEnclave), passing the task id
        4. VTL1 is now running on a different thread and has the task id(!!)
        5. VTL1 retrieves the task (lambda) using the task id and runs the task's lambda
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
    weak_object_table<keepalive_hold<taskpool>>& get_taskpool_object_table();
}

// impl
namespace veil::vtl1
{
    struct taskpool
    {
    public:
        taskpool(uint32_t threadCount, bool mustFinishAllQueuedTasks = true)
            : m_keepalive(this)
        {
            // store this taskpool (weakly) into a global table of taskpools (and get a unique id)
            m_objectTableEntryId = veil::vtl1::implementation::get_taskpool_object_table().store(m_keepalive.get_weak());

            ENCLAVE_INFORMATION enclaveInformation;
            THROW_IF_FAILED(EnclaveGetEnclaveInformation(sizeof(ENCLAVE_INFORMATION), &enclaveInformation));
            void* enclave = enclaveInformation.BaseAddress;

            auto makeTaskpoolArgs = veil::vtl1::vtl0_functions::allocate<veil::any::implementation::args::taskpool_make>();

            void* output{};
            auto makeTaskpool = veil::vtl1::implementation::get_callback(veil::implementation::callback_id::taskpool_make);
            makeTaskpoolArgs->enclave = enclave;
            makeTaskpoolArgs->taskpoolInstanceVtl1 = (uint64_t)(m_objectTableEntryId);
            makeTaskpoolArgs->threadCount = threadCount;
            makeTaskpoolArgs->mustFinishAllQueuedTasks = mustFinishAllQueuedTasks;
            THROW_IF_WIN32_BOOL_FALSE(CallEnclave(makeTaskpool, reinterpret_cast<void*>(makeTaskpoolArgs), TRUE, reinterpret_cast<void**>(&output)));

            m_vtl1_taskpool_vtl0_backing_threads_instance = makeTaskpoolArgs->taskpoolInstanceVtl0;
        }

        ~taskpool()
        {
            void* output{};
            auto deleteTaskpool = veil::vtl1::implementation::get_callback(veil::implementation::callback_id::taskpool_delete);
            
            THROW_IF_WIN32_BOOL_FALSE(CallEnclave(deleteTaskpool, reinterpret_cast<void*>(m_vtl1_taskpool_vtl0_backing_threads_instance), TRUE, reinterpret_cast<void**>(&output)));

            // erase weak reference from weak object table
            veil::vtl1::implementation::get_taskpool_object_table().erase(m_objectTableEntryId);

            // stay alive if someone is holding a strong reference to the "keepalive_hold" (strong-reference to the weak-entry in the weak object table)
            m_keepalive.release_hold_and_block();
        }

        template <typename F>
        [[nodiscard]] auto queue_task(F&& f) -> veil::vtl1::future<decltype(f())>
        {
            using return_type = decltype(f());

            void* allocation = veil::vtl1::vtl0_functions::malloc(sizeof(veil::any::implementation::args::taskpool_schedule_task));
            THROW_IF_NULL_ALLOC(allocation);

            // Store the task
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
                    catch (...) {
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
                    catch (...) {
                        p->set_exception(std::current_exception());
                    }
                }
            };

            //UINT64 taskHandle = store_task(std::move(func));
            auto taskHandle = m_tasks.store(std::move(func));

            auto taskHandleArgs = reinterpret_cast<veil::any::implementation::args::taskpool_schedule_task*>(allocation);
            taskHandleArgs->taskpoolInstanceVtl0 = m_vtl1_taskpool_vtl0_backing_threads_instance;
            taskHandleArgs->taskId = taskHandle;

            void* output{};
            auto vtl0_scheduleTask_callback = (LPENCLAVE_ROUTINE)veil::vtl1::implementation::get_callback(veil::implementation::callback_id::taskpool_schedule_task);
            THROW_IF_WIN32_BOOL_FALSE(CallEnclave(vtl0_scheduleTask_callback, reinterpret_cast<void*>(taskHandleArgs), TRUE, reinterpret_cast<void**>(&output)));

            //return std::move(fut);
            return fut;
        }

        void run_task(UINT64 taskHandle)
        {
            // Lock
            // 
            // 
            


            //std::scoped_lock lock(m_mutex);
            /*
            auto task = m_tasks.try_take_object(task_handle);
            if (!task)
            {
                THROW_WIN32_MSG(ERROR_INVALID_INDEX, "Task handle doesn't exist: %d", (int)taskHandle);
            }

            auto& task_lambda = *task.get();

            // Finally run the task, which is a std::function<void()> that,
            //  1. Runs the captured user-provided lambda
            //  2. Runs the promise setter (so the user's future is live)
            task_lambda();

            // Free the task
            task.reset();
            */

            // Remove the task entry from the unique_object_table
            auto task = m_tasks.try_take(taskHandle);
            if (!task)
            {
                THROW_WIN32_MSG(ERROR_INVALID_INDEX, "Task handle doesn't exist: %d", (int)taskHandle);
            }

            auto& task_lambda = task.value();

            // Finally run the task, which is a std::function<void()> that,
            //  1. Runs the captured user-provided lambda
            //  2. Runs the promise setter (so the user's future is live)
            task_lambda();

            // The task, std::function<void()>, is freed...
        }

        /*
        static taskpool* resolve_taskpool(unique_object_table<taskpool>::handle handle)
        {
            // todo: lock
            m_taskpools.
        }
        */

    private:

        // std::map of tasks with handles
        //std::map<UINT64, std::function<void()>> m_tasks;
        //std::mutex m_mutex;

        veil::vtl1::unique_object_table<std::function<void()>> m_tasks;

        void* m_vtl1_taskpool_vtl0_backing_threads_instance{};

        // this is required secure lifetime management
        //keepalive_system<taskpool> m_objectTableEntry;
        veil::vtl1::keepalive_mechanism<taskpool> m_keepalive;
        size_t m_objectTableEntryId{};
    };
}


