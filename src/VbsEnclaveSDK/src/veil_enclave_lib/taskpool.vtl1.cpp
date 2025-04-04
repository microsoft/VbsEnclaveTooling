// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "pch.h"

#include <functional>
#include <map>
#include <mutex>
#include <vector>

#include "..\veil_any_inc\veil.any.h"

#include "taskpool.vtl1.h"


// object table entries
namespace veil::vtl1::implementation
{
    weak_object_table<keepalive_object_proxy<taskpool>>& get_taskpool_object_table()
    {
        static weak_object_table<keepalive_object_proxy<taskpool>> s_taskpoolWeakReferences;
        return s_taskpoolWeakReferences;
    }
}

// call ins
namespace veil::vtl1::implementation::exports
{
    // A VTL0 backing thread calls this entrypoint to (finally) run the task via its id
    HRESULT taskpool_run_task(_Inout_ veil::any::implementation::args::taskpool_run_task* params)
    try
    {
        auto taskpoolId = params->taskpoolInstanceVtl1;

        if (auto objectProxy = get_taskpool_object_table().resolve_strong_reference(taskpoolId))
        {
            // We have a strong-reference to an object_proxy that keeps the taskpool alive.
            //  (The taskpool's dtor has promised to block until we release all strong references
            //   to the object_proxy)

            // Get the taskpool
            auto& taskpoolInstance = objectProxy->object();

            // Run the task
            taskpoolInstance.run_task(params->taskId);

            return S_OK;
        }

        THROW_HR(HRESULT_FROM_WIN32(ERROR_RESOURCE_NOT_ONLINE)); // ERROR_NOT_READY? ERROR_INVALID_STATE?
    }
    CATCH_RETURN()
}
