#include "pch.h"

#include <functional>
#include <map>
#include <mutex>
#include <vector>

#include <veil.any.h>

#include "threadpool.vtl1.h"


// object table entries
namespace veil::vtl1::implementation
{
    weak_object_table<keepalive_hold<threadpool>>& get_threadpool_object_table()
    {
        static weak_object_table<keepalive_hold<threadpool>> s_threadpoolWeakReferences;
        return s_threadpoolWeakReferences;
    }
}

// call ins
namespace veil::vtl1::implementation::call_ins
{
    HRESULT threadpool_run_task(_Inout_ veil::any::implementation::args::threadpool_run_task* params)
    try
    {
        auto taskInfo = reinterpret_cast<veil::any::implementation::threadpool_task_handle*>(params);

        auto keepaliveMaybeChit = (size_t)taskInfo->threadpool_instance;

        if (auto keepaliveHold = get_threadpool_object_table().resolve_strong_reference(keepaliveMaybeChit))
        {
            // We have keepalive hold
            //  i.e. a strong reference (std::shared_ptr) to the keepalive_hold object of the threadpool.
            //  (The threadpool's dtor has promised to block)
            auto threadpoolInstance = keepaliveHold->object();

            // Run the task
            threadpoolInstance->run_task(taskInfo->task_handle);

            return S_OK;
        }

        THROW_HR(HRESULT_FROM_WIN32(ERROR_RESOURCE_NOT_ONLINE)); // ERROR_NOT_READY? ERROR_INVALID_STATE?
    }
    CATCH_RETURN()
}
