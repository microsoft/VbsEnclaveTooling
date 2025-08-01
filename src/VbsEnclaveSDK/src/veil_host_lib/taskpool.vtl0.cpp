// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "pch.h"

#define VEIL_IMPLEMENTATION

#include <VbsEnclave\HostApp\Implementation\Untrusted.h>
#include <VbsEnclave\HostApp\Stubs\Trusted.h>

#include "taskpool.any.h"
#include "taskpool.vtl0.h"


namespace abi = veil::any::implementation::taskpool;

HRESULT veil_abi::Untrusted::Implementation::taskpool_make(_In_ uintptr_t enclave, _In_ std::uint64_t taskpool_instance_vtl1, _In_ std::uint32_t thread_count, _In_ bool must_finish_all_queued_tasks, _Out_  uintptr_t& taskpool_instance_vtl0)
{
    auto taskpoolInstanceVtl0 = std::make_unique<veil::vtl0::implementation::taskpool_backing_threads>(abi::from_abi(enclave), taskpool_instance_vtl1, thread_count, must_finish_all_queued_tasks);
    taskpool_instance_vtl0 = reinterpret_cast<uint64_t>(taskpoolInstanceVtl0.release()); // let the vtl0 counterpart be owned by vtl1 taskpool
    return S_OK;
}

HRESULT veil_abi::Untrusted::Implementation::taskpool_delete(_In_ uintptr_t taskpool_instance_vtl0)
{
    using T = veil::vtl0::implementation::taskpool_backing_threads;
    auto taskpoolInstanceVtl0 = std::unique_ptr<T>(reinterpret_cast<T*>(taskpool_instance_vtl0));
    taskpoolInstanceVtl0.reset(); // deleting explicitly for clarity
    return S_OK;
}

HRESULT veil_abi::Untrusted::Implementation::taskpool_schedule_task(_In_ uintptr_t taskpool_instance_vtl0, _In_ std::uint64_t task_id)
{
    auto taskpoolInstance = reinterpret_cast<veil::vtl0::implementation::taskpool_backing_threads*>(taskpool_instance_vtl0);
    taskpoolInstance->queue_task(task_id);
    return S_OK;
}

HRESULT veil_abi::Untrusted::Implementation::taskpool_cancel_queued_tasks(_In_ uintptr_t taskpool_instance_vtl0)
{
    using T = veil::vtl0::implementation::taskpool_backing_threads;
    auto taskpoolInstanceVtl0 = reinterpret_cast<T*>(taskpool_instance_vtl0);
    taskpoolInstanceVtl0->cancel_queued_tasks();
    return S_OK;
}

namespace veil::vtl0::implementation::callins
{
HRESULT taskpool_run_task(_In_ void* enclave, _In_ const std::uint64_t taskpool_instance_vtl1, _In_ const std::uint64_t task_id)
{
    // Initialize enclave interface
    auto enclaveInterface = veil_abi::Trusted::Stubs::export_interface(enclave);
        THROW_IF_FAILED(enclaveInterface.RegisterVtl0Callbacks());

        THROW_IF_FAILED(enclaveInterface.taskpool_run_task(taskpool_instance_vtl1, task_id));
        return S_OK;
    }
}
