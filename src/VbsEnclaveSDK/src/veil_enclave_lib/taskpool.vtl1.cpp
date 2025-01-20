#include "pch.h"

#include <functional>
#include <map>
#include <mutex>
#include <vector>

#include <veil.any.h>

#include "taskpool.vtl1.h"


// object table entries
namespace veil::vtl1::implementation
{
    weak_object_table<keepalive_hold<taskpool>>& get_taskpool_object_table()
    {
        static weak_object_table<keepalive_hold<taskpool>> s_taskpoolWeakReferences;
        return s_taskpoolWeakReferences;
    }
}

// call ins
namespace veil::vtl1::implementation::exports
{
    HRESULT taskpool_run_task(_Inout_ veil::any::implementation::args::taskpool_run_task* params)
    try
    {
        auto taskpoolId = params->taskpoolInstanceVtl1;

        if (auto keepaliveHold = get_taskpool_object_table().resolve_strong_reference(taskpoolId))
        {
            // We have keepalive hold
            //  i.e. a strong reference (std::shared_ptr) to the keepalive_hold object of the taskpool.
            //  (The taskpool's dtor has promised to block)
            auto taskpoolInstance = keepaliveHold->object();

            // Run the task
            taskpoolInstance->run_task(params->taskId);

            return S_OK;
        }

        THROW_HR(HRESULT_FROM_WIN32(ERROR_RESOURCE_NOT_ONLINE)); // ERROR_NOT_READY? ERROR_INVALID_STATE?
    }
    CATCH_RETURN()
}
