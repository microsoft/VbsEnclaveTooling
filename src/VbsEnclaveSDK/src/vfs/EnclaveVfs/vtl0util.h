// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <winenclaveapi.h>
#include <unordered_map>
#include "enclave_vfs.h"

HRESULT VerifyVtl0Memory(_In_ LPCVOID vtl0ptr, size_t size);
HRESULT VerifyAndReadVtl0Memory(_In_ LPCVOID vtl0Src, size_t size, _In_ PVOID vtl1Dest);
HRESULT GetSharedMemoryForThread(_Outptr_ Vtl0SharedMemoryBuffer** sharedMemory);

template<auto fn, typename T>
int CallVtl0VfsFunction(T& context)
{
    extern Vtl0VfsCallbacks g_vtl0VfsCallbacks;
    int CallVtl0VfsFunctionWithSizedBuffer(_In_ PENCLAVE_ROUTINE function, _In_ size_t contextSize, _Inout_ WinLastErrorContext* context);

    static_assert(std::is_same_v<T, typename Vtl0AssociatedContext<fn>::type>,
        "Wrong payload type for VFS callback function");
    static_assert(sizeof(T) <= sizeof(Vtl0SharedMemoryBuffer),
        "You need to add the context type to the union in Vtl0SharedMemoryBuffer.");
    return CallVtl0VfsFunctionWithSizedBuffer(g_vtl0VfsCallbacks.*fn, sizeof(T), &context);
}
