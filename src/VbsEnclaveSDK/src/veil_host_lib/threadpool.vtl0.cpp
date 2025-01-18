#include "pch.h"

#include <deque>
#include <mutex>
#include <vector>
#include <thread>

#include "threadpool.vtl0.h"

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

//
// Shared Code
//
/*
struct threadpool_task_handle
{
    void* threadpool_instance;
    UINT64 task_handle;
};
*/

/*
//

// Host app code (VTL0)
//

// Enclave threadpool implementation (in VTL0 - client side)

namespace eif_client::implementation
{
    struct vtl1_threadpool_vtl0_backing_threads
    {
    public:
        // Make sure the threadCount is at most [IMAGE_ENCLAVE_CONFIG.NumberOfThreads - 1] so the
        // enclave always has a thread of execution, and prevent deadlociking the enclave.
        vtl1_threadpool_vtl0_backing_threads(void* enclave, size_t threadCount = 1) : m_enclave(enclave)
        {
            for (size_t i = 0; i < threadCount; i++)
            {
                m_threads.emplace_back([this]() { threadproc(); });
            }
        }

        ~vtl1_threadpool_vtl0_backing_threads()
        {
            m_stop = true;
            m_cv.notify_all();
            for (auto& t : m_threads)
            {
                t.join();
            }
        }

        HRESULT add_task(UINT64 task_handle)
        try
        {
            {
                std::lock_guard lock(m_mutex);
                m_taskHandles.push_back(task_handle);
            }
            m_cv.notify_one();
            return S_OK;
        }
        CATCH_RETURN()

    private:
        void threadproc()
        {
            while (!m_stop)
            {
                UINT64 taskHandle;
                {
                    std::unique_lock lock(m_mutex);
                    m_cv.wait(lock, [this]() { return m_stop || !m_taskHandles.empty(); });
                    if (m_stop)
                    {
                        break;
                    }
                    taskHandle = std::move(m_taskHandles.front());
                    m_taskHandles.pop_front();
                }

                // Signal VTL1 to run the task - this is a blocking call, even if there is no VTL1 thread ready
                void* output{};
                veil::any::implementation::args::StartHelloSession data = {};
                THROW_IF_FAILED(enclave_model_api::CallEnclaveModelApi_CallByOrdinal(m_enclave, export_ordinals::StartHelloSession, data));
                //THROW_IF_FAILED(enclave_model_api::CallEnclaveModelApi_CallByOrdinal(enclave, export_ordinals::threadpool_run_task, data));
                //LOG_IF_WIN32_BOOL_FALSE(CallEnclave(routine, reinterpret_cast<void*>(taskHandle), TRUE, reinterpret_cast<void**>(&output)));
            }
        }

        void* m_enclave{};
        std::vector<std::thread> m_threads;
        std::deque<UINT64> m_taskHandles;
        std::mutex m_mutex;
        std::condition_variable m_cv;
        bool m_stop = false;
    };
}

*/


namespace veil::vtl0::implementation::callbacks
{
    VEIL_ABI_FUNCTION(threadpool_make, args,
    {
        auto makeArgs = reinterpret_cast<veil::any::implementation::args::threadpool_make*>(args);

        auto threadpool = new veil::vtl0::implementation::threadpool_backing_threads(makeArgs->enclave, makeArgs->threadpoolInstanceVtl1, makeArgs->threadCount, makeArgs->mustFinishAllQueuedTasks);
        //g_threadpool = threadpool;

        makeArgs->threadpoolInstanceVtl0 = reinterpret_cast<void*>(threadpool);

        // todo: how to delete

        return S_OK;
    })

    VEIL_ABI_FUNCTION(threadpool_delete, args,
    {
        auto threadpoolVtl0 = reinterpret_cast<veil::vtl0::implementation::threadpool_backing_threads*>(args);
        auto threadpoolForDeletion = std::unique_ptr<veil::vtl0::implementation::threadpool_backing_threads>(threadpoolVtl0);
        //Sleep(1000);
        return S_OK;
    })

    VEIL_ABI_FUNCTION(threadpool_schedule_task, args,
    {
        auto taskInfo = reinterpret_cast<veil::any::implementation::args::threadpool_schedule_task*>(args);
        auto threadpoolInstance = reinterpret_cast<veil::vtl0::implementation::threadpool_backing_threads*>(taskInfo->threadpoolInstanceVtl0);
        //auto threadpoolInstance = g_threadpool;
        RETURN_IF_FAILED(threadpoolInstance->add_task(taskInfo->taskHandle));

        /*
        auto threadpoolInstance = g_threadpool;

        auto taskInfo = reinterpret_cast<veil::any::implementation::threadpool_task_handle*>(args);
        RETURN_IF_FAILED(threadpoolInstance->add_task(taskInfo->task_handle));
        */
        return S_OK;
    })
}
