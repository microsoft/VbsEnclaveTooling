// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "pch.h"
#include <atomic>
#include <safeint.h>

#include "enclavethreading.h"

#include "enclave_vfs.h"
#include "utils.h"
#include "data_enclave.h" // HRESULT/SQLITE interop helpers
#include "vtl0util.h"

#include "EnclaveServices.h"

HRESULT VerifyVtl0Memory(_In_ LPCVOID vtl0ptr, size_t size)
{
#ifndef NORMAL_MODE
    return CheckForVTL0Buffer(vtl0ptr, size);
#else
	return S_OK;
#endif
}

HRESULT VerifyAndReadVtl0Memory(_In_ LPCVOID vtl0Src, size_t size, _In_ PVOID vtl1Dest)
{
    RETURN_HR_IF(E_INVALIDARG, vtl0Src == nullptr || vtl1Dest == nullptr);

#ifndef NORMAL_MODE
    RETURN_IF_FAILED(CopyFromVTL0ToVTL1(vtl1Dest, vtl0Src, size));
#else
    memcpy_s(vtl1Dest, size, vtl0Src, size);
#endif // !NORMAL_MODE
    
    return S_OK;
}

extern std::atomic<Vtl0SharedMemoryBuffer*> g_vtl0SharedMemory;

HRESULT GetSharedMemoryForThread(_Outptr_ Vtl0SharedMemoryBuffer** sharedMemory)
{
	*sharedMemory = nullptr;

    auto currentThreadIndex = GetCurrentEnclaveThreadIndex();
    assert(currentThreadIndex != -1 && currentThreadIndex < ENCLAVE_MAX_THREADS);

    RETURN_HR_IF(E_UNEXPECTED, currentThreadIndex < 0 || currentThreadIndex >= ENCLAVE_MAX_THREADS);
    // g_vtl0SharedMemory is known to be non-null because RegisterWin32eVfs would not have registered the
    // VFS callbacks without it. And ConfigureEnclaveVfs validated that g_vtl0SharedMemory points to an
    // array of ENCLAVE_MAX_THREADS elements in VTL0.
    *sharedMemory = &g_vtl0SharedMemory.load(std::memory_order_relaxed)[currentThreadIndex];
    return S_OK;
}

HRESULT CallVtl0VfsFunctionImpl(_In_ PENCLAVE_ROUTINE function, _In_ size_t contextSize, _Inout_ WinLastErrorContext* context)
{
    context->lastError = ERROR_INVALID_FUNCTION;
    auto setLastError = wil::scope_exit([&]
    {
        SetLastError(context->lastError);
    });

    RETURN_IF_FAILED(CheckForVTL0Function(function));

	// Get the VTL0 Shared memory for this thread
	Vtl0SharedMemoryBuffer* sharedMemory = nullptr;
    RETURN_IF_FAILED(GetSharedMemoryForThread(&sharedMemory));

    // Should never happen: This means that somebody is using a structure that was never
    // added to Vtl0SharedMemoryBuffer.
    RETURN_HR_IF(SQLITE_E_NOMEM, contextSize > sizeof(sharedMemory->data));

    // Copy parameters to the shared memory in VTL0
    memcpy_s(&sharedMemory->data, sizeof(sharedMemory->data), context, contextSize);

	PVOID retVal;
	BOOL status = TRUE;
#ifdef NORMAL_MODE
	retVal = function(sharedMemory);
    ::SetLastError(ERROR_SUCCESS);
#else
	status = GetEnclaveServices().CallEnclave(function, &sharedMemory->data, TRUE, &retVal);
#endif
    RETURN_HR_IF(SQLITE_E_INTERNAL, !status);

    // Copy any changes to the buffer back into VTL1 in case there are any OUT parameters.
    memcpy_s(context, contextSize, &sharedMemory->data, contextSize);

	return HRESULT_FROM_SQLITE_RESULT(PtrToInt(retVal));
}

int CallVtl0VfsFunctionWithSizedBuffer(_In_ PENCLAVE_ROUTINE function, _In_ size_t contextSize, _Inout_ WinLastErrorContext* context)
{
    return SqliteResultFromHRESULT(CallVtl0VfsFunctionImpl(function, contextSize, context));
}
