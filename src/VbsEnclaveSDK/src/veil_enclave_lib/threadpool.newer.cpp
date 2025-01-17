//
// Shraed Code
//

struct threadpool_task_handle
{
    void* threadpool_instance;
    UINT64 task_handle;
};


//
// Host app code (VTL0)
//

// Enclave threadpool implementation (in VTL0 - client side)
extern "C" PVOID EnclaveImplementationFramework_Vtl0_Threadpool_ScheduleTask(PVOID args)
{
    auto hr = ([&]() -> HRESULT
    {
        auto taskInfo = reinterpret_cast<threadpool_task_handle*>(args);
        auto threadpoolInstance = reinterpret_cast<eif_client::implementation::vtl1_threadpool_vtl0_backing_threads*>(taskInfo->threadpool_instance);
        RETURN_IF_FAILED(threadpoolInstance->add_task(taskInfo->task_handle));
        return S_OK;
    })();
    RETURN_HR_AS_PVOID(hr);
}

namespace eif_client::implementation
{
    struct vtl1_threadpool_vtl0_backing_threads
    {
    public:
        // Make sure the threadCount is at most [IMAGE_ENCLAVE_CONFIG.NumberOfThreads - 1] so the
        // enclave always has a thread of execution, and prevent deadlociking the enclave.
        vtl1_threadpool_vtl0_backing_threads(size_t threadCount = 1)
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
                UINT64 task;
                {
                    std::unique_lock lock(m_mutex);
                    m_cv.wait(lock, [this]() { return m_stop || !m_taskHandles.empty(); });
                    if (m_stop)
                    {
                        break;
                    }
                    taskHandle = std::move(m_tasks.front());
                    m_taskHandles.pop_front();
                }

                // Signal VTL1 to run the task
                void* output{};
                LOG_IF_WIN32_BOOL_FALSE(CallEnclave(routine, reinterpret_cast<void*>(taskHandle), TRUE, reinterpret_cast<void**>(&output)));
            }
        }

        std::vector<std::thread> m_threads;
        std::deque<UINT64> m_taskHandles;
        std::mutex m_mutex;
        std::condition_variable m_cv;
        bool m_stop = false;
    };
}


//
// Enclave code (VTL1)
//

// Enclave threadpool implementation (in VTL1 - server side)
namespace eif_server::enclave_interface
{
    struct vtl1_threadpool
    {
    public:
        vtl1_threadpool()
        {
            m_vtl1_threadpool_vtl0_backing_threads_instance = GetVtl0ThreadpoolBackingThreadsInstance();
            m_vtl0_scheduleTask_callback = GetCallbackRoutine(L"EnclaveImplementationFramework_Vtl0_Threadpool_ScheduleTask");
        }

        HRESULT add_task(std::function<void()> task)
        try
        {
            // Store the task
            UINT64 taskHandle = store_task(task);

            auto arguments = threadpool_task_handle{
                m_vtl1_threadpool_vtl0_backing_threads_instance,
                taskHandle
            };

            void* output{};
            THROW_IF_WIN32_BOOL_FALSE(CallEnclave(m_vtl0_scheduleTask_callback, reinterpret_cast<void*>(&arguments), TRUE, reinterpret_cast<void**>(&output)));
        }
        CATCH_RETURN()

    private:
        UINT64 store_task(std::function<void()> task)
        {
            static uint32_t handle = 0;
            m_tasks.push_back(std::make_pair(handle++, task));
            return handle;
        }

        // std::deque of tasks with handles
        std::deque<std::pair<UINT64, std::function<void()>>> m_tasks;

        void* m_vtl1_threadpool_vtl0_backing_threads_instance{};
        void* m_vtl0_scheduleTask_callback{};
    };
}


// Sample usage
void myEnclaveFunction()
{
    auto threadpool = eif_server::enclave_interface::vtl1_threadpool{};
    threadpool.add_task([]() {
        // Do work
    });
}
