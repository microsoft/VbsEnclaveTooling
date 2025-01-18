#pragma once

#include <functional>
#include <map>

#include "future.vtl1.h"
#include "object_table.vtl1.h"
#include "registered_callbacks.vtl1.h"
#include "vtl0_functions.vtl1.h"

#include "veil_arguments.any.h"

/*

Usage...

    void usage()
    {
        auto threadpool = eif_server::enclave_interface::vtl1_threadpool{};  // create and store this in a global somewhere

        auto task1 = threadpool.queue_task([]() {
            // Do work
        });

        auto task2 = threadpool.queue_task([]() {
            // Do work
        });

        auto task3 = threadpool.queue_task([]() {
            // Do work
            return 55;
        });

        task1.get();
        task2.get();
        int x = task3.get();  // 55
    }


Implementation...

    This is a threadpool designed to be used in VTL1.  VTL1 cannot create threads or schedule work onto threads.
    To work around this limitation, a backing VTL0 thread will act as a conduit to get a task scheduled on
    a different, available, thread in VTL1.

    Task scheduling flow mechanics:/
        0. VTL1 app enclave consumer calls threadpool's add_task(task_lambda)
        1. VTL1 threadpool stores the task (lambda) + task handle
        2. VTL1 calls out to VTL0, passing the task handle
        3. VTL0 finds an available thread (from VTL0 backing threadpool) to call CallEnclave, passing the task handle, to get back into VTL1
        4. VTL1 is now running on a different thread(!!)
        5. VTL1 retrieves the task (lambda) using the task handle and runs the task
*/

// fwd decls
namespace veil::vtl1
{
    struct threadpool;
}

// call ins
namespace veil::vtl1::implementation::exports
{
    HRESULT threadpool_run_task(_Inout_ veil::any::implementation::args::threadpool_run_task* params);
}

// object table entries
namespace veil::vtl1::implementation
{
    weak_object_table<keepalive_hold<threadpool>>& get_threadpool_object_table();
    //size_t insert_weak_object_table_entry(std::weak_ptr<veil::vtl1::keepalive_hold<veil::vtl1::threadpool>> keepaliveHandle);
    //void erase_weak_object_table_entry(size_t handle);

    //using unique_object_table_entry = wil::unique_any<size_t, decltype(&erase_weak_object_table_entry), erase_weak_object_table_entry>;
}

// impl
namespace veil::vtl1
{
    struct threadpool
    {
    public:
        threadpool(uint32_t threadCount, bool mustFinishAllQueuedTasks = true)
            : m_keepalive(this)
        {
            // store this threadpool (weakly) into a global table of threadpools (and get a unique id)
            m_objectTableEntryId = veil::vtl1::implementation::get_threadpool_object_table().store(m_keepalive.get_weak());

            //void* allocation = veil::vtl1::vtl0_functions::malloc(sizeof(veil::any::implementation::args::threadpool_make));
            //THROW_IF_NULL_ALLOC(allocation);

            ENCLAVE_INFORMATION enclaveInformation;
            THROW_IF_FAILED(EnclaveGetEnclaveInformation(sizeof(ENCLAVE_INFORMATION), &enclaveInformation));
            void* enclave = enclaveInformation.BaseAddress;

            //auto makeThreadpoolArgs = reinterpret_cast<veil::any::implementation::args::threadpool_make*>(allocation);
            auto makeThreadpoolArgs = veil::vtl1::vtl0_functions::allocate<veil::any::implementation::args::threadpool_make>();

            void* output{};
            auto makeThreadpool = veil::vtl1::implementation::get_callback(veil::implementation::callback_id::threadpool_make);
            makeThreadpoolArgs->enclave = enclave;
            makeThreadpoolArgs->threadpoolInstanceVtl1 = (uint64_t)(m_objectTableEntryId);
            makeThreadpoolArgs->threadCount = threadCount;
            makeThreadpoolArgs->mustFinishAllQueuedTasks = mustFinishAllQueuedTasks;
            THROW_IF_WIN32_BOOL_FALSE(CallEnclave(makeThreadpool, reinterpret_cast<void*>(makeThreadpoolArgs), TRUE, reinterpret_cast<void**>(&output)));

            m_vtl1_threadpool_vtl0_backing_threads_instance = makeThreadpoolArgs->threadpoolInstanceVtl0;
        }

        ~threadpool()
        {
            void* output{};
            auto deleteThreadpool = veil::vtl1::implementation::get_callback(veil::implementation::callback_id::threadpool_delete);
            
            THROW_IF_WIN32_BOOL_FALSE(CallEnclave(deleteThreadpool, reinterpret_cast<void*>(m_vtl1_threadpool_vtl0_backing_threads_instance), TRUE, reinterpret_cast<void**>(&output)));

            // erase weak reference from weak object table
            veil::vtl1::implementation::get_threadpool_object_table().erase(m_objectTableEntryId);

            // stay alive if someone is holding a strong reference to the "keepalive_hold" (strong-reference to the weak-entry in the weak object table)
            m_keepalive.reset_keepalive_and_block();
        }

        template <typename F>
        [[nodiscard]] auto queue_task(F&& f) -> veil::vtl1::future<decltype(f())>
        {
            using return_type = decltype(f());

            void* allocation = veil::vtl1::vtl0_functions::malloc(sizeof(veil::any::implementation::args::threadpool_schedule_task));
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
            auto taskHandle = m_tasks.store_object(std::move(func));

            auto taskHandleArgs = reinterpret_cast<veil::any::implementation::args::threadpool_schedule_task*>(allocation);
            taskHandleArgs->threadpoolInstanceVtl0 = m_vtl1_threadpool_vtl0_backing_threads_instance;
            taskHandleArgs->taskHandle = taskHandle;

            void* output{};
            auto vtl0_scheduleTask_callback = (LPENCLAVE_ROUTINE)veil::vtl1::implementation::get_callback(veil::implementation::callback_id::threadpool_schedule_task);
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
            auto task = m_tasks.try_take_object(taskHandle);
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
        static threadpool* resolve_threadpool(unique_object_table<threadpool>::handle handle)
        {
            // todo: lock
            m_threadpools.
        }
        */

    private:

        // std::map of tasks with handles
        //std::map<UINT64, std::function<void()>> m_tasks;
        //std::mutex m_mutex;

        veil::vtl1::unique_object_table<std::function<void()>> m_tasks;

        void* m_vtl1_threadpool_vtl0_backing_threads_instance{};

        // this is required secure lifetime management
        //keepalive_system<threadpool> m_objectTableEntry;
        veil::vtl1::keepalive_mechanism<threadpool> m_keepalive;
        size_t m_objectTableEntryId{};
    };
}


