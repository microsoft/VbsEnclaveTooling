#pragma once

#include <deque>
#include <future>
#include <mutex>
#include <vector>
#include <thread>

#include "veil.any.h"
#include "veil_arguments.any.h"

#include "enclave_api.vtl0.h"
#include "exports.vtl0.h"

/*
This is a threadpool designed to be used in VTL1.  VTL1 cannot create threads or schedule work onto threads. 
To work around this limitation, a backing VTL0 thread will act as a conduit to get a task scheduled on
a different, available, thread in VTL1.

Task scheduling flow mechanics:
    0. VTL1 app enclave consumer calls threadpool's add_task(task_lambda)
    1. VTL1 threadpool stores the task (lambda) + task handle
    2. VTL1 calls out to VTL0, passing the task handle
    3. VTL0 finds an available thread (from VTL0 backing threadpool) to call CallEnclave, passing the task handle, to get back into VTL1
    4. VTL1 is now running on a different thread(!!)
    5. VTL1 retrieves the task (lambda) using the task handle and runs the task
*/


namespace veil::vtl0::implementation::callbacks
{
    void* threadpool_make(void* args);
    void* threadpool_delete(void* args);
    void* threadpool_schedule_task(void* args);
}

// vtl0 code - vtl0 threads that back the vtl1 threadpool implementation
namespace veil::vtl0::implementation
{
    struct threadpool_backing_threads
    {
    public:
        // Make sure the threadCount is at most [IMAGE_ENCLAVE_CONFIG.NumberOfThreads - 1] so the
        // enclave always has a thread of execution, and prevent deadlocking the enclave.
        threadpool_backing_threads(void* enclave, uint64_t threadpoolInstance_vtl1, size_t threadCount = 1, bool mustFinishAllQueuedTasks = true)
            : m_enclave(enclave), m_threadpoolInstance_vtl1(threadpoolInstance_vtl1), m_mustFinishAllQueuedTasks(mustFinishAllQueuedTasks)
        {
            for (size_t i = 0; i < threadCount; i++)
            {
                m_threads.emplace_back([this]() { thread_proc(); });
            }
        }

        ~threadpool_backing_threads()
        {
            {
                std::unique_lock lock(m_mutex);
                m_stop = true;
            }
            m_cv.notify_all();
            for (auto& t : m_threads)
            {
                t.join();
            }
        }

        HRESULT add_task(UINT64 task_handle) try
        {
            {
                std::lock_guard lock(m_mutex);
                if (m_stop)
                {
                    RETURN_HR(HRESULT_FROM_WIN32(ERROR_CANCELLED));
                }
                m_taskHandles.push_back(task_handle);
            }
            m_cv.notify_one();
            return S_OK;
        }
        CATCH_RETURN()

    private:
        void thread_proc()
        {
            while (true)
            {
                // Wait for task
                {
                    std::unique_lock lock(m_mutex);
                    m_cv.wait(lock, [this]() { return m_stop || !m_taskHandles.empty(); });
                }

                // Maybe terminate thread
                if (m_stop)
                {
                    if (!m_mustFinishAllQueuedTasks)
                    {
                        break;
                    }

                    std::unique_lock lock(m_mutex);
                    if (m_taskHandles.empty())
                    {
                        break;
                    }
                }

                // Dequeue task
                UINT64 taskHandle;
                {
                    std::unique_lock lock(m_mutex);
                    if (m_taskHandles.empty())
                    {
                        continue;
                    }
                    taskHandle = std::move(m_taskHandles.front());
                    m_taskHandles.pop_front();
                }

                // Run task
                //      Signal VTL1 to run the task - this is a blocking call, even if there is no VTL1 thread ready
                veil::any::implementation::args::threadpool_run_task data = {};
                data.threadpoolInstance = m_threadpoolInstance_vtl1;
                data.taskHandle = taskHandle;
                THROW_IF_FAILED(veil::vtl0::enclave::implementation::call_enclave_function(m_enclave, veil::implementation::export_ordinals::threadpool_run_task, data));
            }
        }

        void* m_enclave{};
        uint64_t m_threadpoolInstance_vtl1{};
        std::vector<std::thread> m_threads;
        std::deque<UINT64> m_taskHandles;
        std::mutex m_mutex;
        std::condition_variable m_cv;
        std::atomic<bool> m_stop = false;
        const bool m_mustFinishAllQueuedTasks;
    };
}
