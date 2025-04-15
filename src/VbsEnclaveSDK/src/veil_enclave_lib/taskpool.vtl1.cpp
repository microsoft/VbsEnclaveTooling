// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "pch.h"

#define VEIL_IMPLEMENTATION

#include <functional>
#include <map>
#include <mutex>
#include <vector>

#include <VbsEnclave\Enclave\Implementations.h>

#include "taskpool.any.h"
#include "taskpool.vtl1.h"


// object table entries
namespace veil::vtl1::implementation
{
    weak_object_table<keepalive_object_proxy<veil::vtl1::taskpool>>& get_taskpool_object_table()
    {
        static weak_object_table<keepalive_object_proxy<veil::vtl1::taskpool>> s_taskpoolWeakReferences;
        return s_taskpoolWeakReferences;
    }
}

// call ins
namespace veil_abi
{
    namespace VTL1_Declarations
    {
        HRESULT taskpool_run_task(_In_ const std::uint64_t taskpool_instance_vtl1, _In_ const std::uint64_t task_id)
        {
            auto taskpoolId = taskpool_instance_vtl1;

            if (auto objectProxy = veil::vtl1::implementation::get_taskpool_object_table().resolve_strong_reference(taskpoolId))
            {
                // We have a strong-reference to an object_proxy that keeps the taskpool alive.
                //  (The taskpool's dtor has promised to block until we release all strong references
                //   to the object_proxy)

                // Get the taskpool
                auto& taskpoolInstance = objectProxy->object();

                // Run the task
                taskpoolInstance.run_task(task_id);

                return S_OK;
            }

            THROW_HR(HRESULT_FROM_WIN32(ERROR_RESOURCE_NOT_ONLINE)); // ERROR_NOT_READY? ERROR_INVALID_STATE?
        }
    }
}

namespace veil::vtl1::implementation::taskpool::callouts
{
    namespace abi = veil::any::implementation::taskpool;

    HRESULT taskpool_make_callback(_In_ const void* enclave, _In_ const std::uint64_t taskpool_instance_vtl1, _In_ const std::uint32_t thread_count, _In_ const bool must_finish_all_queued_tasks, _Out_  void** taskpool_instance_vtl0)
    {
        auto taskpoolInstanceVtl0 = DeveloperTypes::ULongPtr {};
        RETURN_IF_FAILED(veil_abi::VTL0_Callbacks::taskpool_make_callback(
            abi::to_abi(enclave),
            taskpool_instance_vtl1,
            thread_count,
            must_finish_all_queued_tasks,
            taskpoolInstanceVtl0));
        *taskpool_instance_vtl0 = abi::from_abi(taskpoolInstanceVtl0);
        return S_OK;
    }

    HRESULT taskpool_delete_callback(_In_ const void* taskpool_instance_vtl0)
    {
        RETURN_IF_FAILED(veil_abi::VTL0_Callbacks::taskpool_delete_callback(abi::to_abi(taskpool_instance_vtl0)));
        return S_OK;
    }

    HRESULT taskpool_schedule_task_callback(_In_ const void* taskpool_instance_vtl0, _In_ const std::uint64_t task_id)
    {
        RETURN_IF_FAILED(veil_abi::VTL0_Callbacks::taskpool_schedule_task_callback(abi::to_abi(taskpool_instance_vtl0), task_id));
        return S_OK;
    }

    HRESULT taskpool_cancel_queued_tasks_callback(_In_ const void* taskpool_instance_vtl0)
    {
        RETURN_IF_FAILED(veil_abi::VTL0_Callbacks::taskpool_cancel_queued_tasks_callback(abi::to_abi(taskpool_instance_vtl0)));
        return S_OK;
    }

}


