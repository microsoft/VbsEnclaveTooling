#include "pch.h"

#include "taskpool.vtl0.h"

namespace veil::vtl0::implementation::callbacks
{
    VEIL_ABI_FUNCTION(taskpool_make, args,
    {
        auto makeArgs = reinterpret_cast<veil::any::implementation::args::taskpool_make*>(args);
        auto taskpoolInstanceVtl0 = std::make_unique<veil::vtl0::implementation::taskpool_backing_threads>(makeArgs->enclave, makeArgs->taskpoolInstanceVtl1, makeArgs->threadCount, makeArgs->mustFinishAllQueuedTasks);
        makeArgs->taskpoolInstanceVtl0 = reinterpret_cast<void*>(taskpoolInstanceVtl0.release());
        return S_OK;
    })

    VEIL_ABI_FUNCTION(taskpool_delete, args,
    {
        //using T = veil::vtl0::implementation::taskpool_backing_threads;
        using T = veil::vtl0::implementation::taskpool_backing_threads;
        auto deleteArgs = reinterpret_cast<veil::any::implementation::args::taskpool_delete*>(args);
        
        auto taskpoolInstanceVtl0 = std::unique_ptr<T>(reinterpret_cast<T*>(deleteArgs->taskpoolInstanceVtl0));
        taskpoolInstanceVtl0.reset(); // delete explicitly
        
        return S_OK;
    })

    VEIL_ABI_FUNCTION(taskpool_schedule_task, args,
    {
        auto taskInfo = reinterpret_cast<veil::any::implementation::args::taskpool_schedule_task*>(args);
        auto taskpoolInstance = reinterpret_cast<veil::vtl0::implementation::taskpool_backing_threads*>(taskInfo->taskpoolInstanceVtl0);
        //auto taskpoolInstance = g_taskpool;
        RETURN_IF_FAILED(taskpoolInstance->queue_task(taskInfo->taskId));



        /*
        auto taskpoolInstance = g_taskpool;

        auto taskInfo = reinterpret_cast<veil::any::implementation::taskpool_task_handle*>(args);
        RETURN_IF_FAILED(taskpoolInstance->add_task(taskInfo->task_handle));
        */
        return S_OK;
    })
}
