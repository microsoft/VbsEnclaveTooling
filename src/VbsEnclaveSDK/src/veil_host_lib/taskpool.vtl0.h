// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <queue>
#include <future>
#include <mutex>
#include <vector>
#include <thread>

#include "veil.any.h"
#include "veil_arguments.any.h"

#include "enclave_api.vtl0.h"
#include "exports.vtl0.h"

//
// See taskpool.vtl1.h for usage.
//

namespace veil::vtl0::implementation::callbacks
{
    void* taskpool_make(void* args) noexcept;
    void* taskpool_delete(void* args) noexcept;
    void* taskpool_schedule_task(void* args) noexcept;
    void* taskpool_cancel_queued_tasks(void* args) noexcept;
}

namespace veil::vtl0::implementation
{
    // vtl0 threads that back the vtl1 taskpool implementation. See taskpool.vtl1.h
    struct taskpool_backing_threads
    {
    public:
        taskpool_backing_threads(void* enclave, uint64_t taskpoolInstance_vtl1, size_t threadCount = 1, bool mustFinishAllQueuedTasks = true)
            : m_enclave(enclave), m_taskpoolInstance_vtl1(taskpoolInstance_vtl1), m_mustFinishAllQueuedTasks(mustFinishAllQueuedTasks)
        {
            for (size_t i = 0; i < threadCount; i++)
            {
                m_threads.emplace_back([this]() { thread_proc(); });
            }
        }

        // Delete copy
        taskpool_backing_threads(const taskpool_backing_threads&) = delete;
        taskpool_backing_threads& operator=(const taskpool_backing_threads&) = delete;

        // Allow move
        taskpool_backing_threads(taskpool_backing_threads&& other) = default;
        taskpool_backing_threads& operator=(taskpool_backing_threads&& other) = default;

        ~taskpool_backing_threads()
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

        void queue_task(uint64_t task_handle)
        {
            {
                std::lock_guard lock(m_mutex);
                if (m_stop)
                {
                    THROW_HR(HRESULT_FROM_WIN32(ERROR_CANCELLED));
                }
                m_taskHandles.push(task_handle);
            }
            m_cv.notify_one();
        }

        void cancel_queued_tasks()
        {
            std::lock_guard lock(m_mutex);
            std::queue<uint64_t>{}.swap(m_taskHandles); // i.e. m_taskHandles.clear()
        }

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
                uint64_t taskHandle;
                {
                    std::unique_lock lock(m_mutex);
                    if (m_taskHandles.empty())
                    {
                        continue;
                    }
                    taskHandle = std::move(m_taskHandles.front());
                    m_taskHandles.pop();
                }

                // Run task
                //      Signal VTL1 to run the task - this is a blocking call, even if there is no VTL1 thread ready
                veil::any::implementation::args::taskpool_run_task data = {};
                data.taskpoolInstanceVtl1 = m_taskpoolInstance_vtl1;
                data.taskId = taskHandle;
                THROW_IF_FAILED(veil::vtl0::enclave::implementation::call_enclave_function(m_enclave, veil::implementation::export_ordinals::taskpool_run_task, data));
            }
        }

        void* m_enclave{};
        uint64_t m_taskpoolInstance_vtl1{};
        std::queue<uint64_t> m_taskHandles;
        std::mutex m_mutex;
        std::condition_variable m_cv;
        std::atomic<bool> m_stop = false;
        const bool m_mustFinishAllQueuedTasks;
        std::vector<std::jthread> m_threads;
    };
}
