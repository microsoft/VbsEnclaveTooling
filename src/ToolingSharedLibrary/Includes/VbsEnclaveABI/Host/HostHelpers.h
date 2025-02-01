// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once 
#include <VbsEnclaveABI\Shared\VbsEnclaveAbiBase.h>
#include <VbsEnclaveABI\Shared\VbsEnclaveMemoryHelpers.h>

// Every function in this file should only be used within the HostApp
namespace VbsEnclaveABI
{
    // Used to allocate vtl0 memory via a pointer from the EnclaveFunctionContext
    // object on demand.
    void* RequestVtl0Memory(void* context)
    {
        auto request = reinterpret_cast<VbsEnclaveABI::EnclaveAllocRequest*>(context);
        return ::HeapAlloc(::GetProcessHeap(), 0, request->size);
    }

    template <typename ParamsT>
    EnclaveFunctionContext SetupVtl1Call(ParamsT* function_params)
    {
        EnclaveFunctionContext function_context {};

        function_context.m_parameters.buffer = function_params;
        function_context.m_parameters.buffer_size = sizeof(ParamsT);
        function_context.m_return_param = nullptr;
        function_context.m_return_param_size = 0;
        function_context.allocator.callback = RequestVtl0Memory;

        return function_context;
    }

    template <typename ParamsT>
    void CallVtl1StubNoResult(void* enclave_instance, std::string_view function_name, ParamsT& function_params)
    {
        
        std::shared_ptr<ParamsT> heap_tuple = std::make_shared<ParamsT>(function_params);
        EnclaveFunctionContext function_context = SetupVtl1Call<ParamsT>(heap_tuple.get());

        auto module = reinterpret_cast<HMODULE>(enclave_instance);
        auto proc_address = GetProcAddress(module, function_name.data());

        auto routine = reinterpret_cast<PENCLAVE_ROUTINE>(proc_address);
        void* result_from_vtl1;

        THROW_IF_WIN32_BOOL_FALSE(CallEnclave(routine, reinterpret_cast<void*>(&function_context), TRUE, &result_from_vtl1));
        THROW_IF_FAILED(PVOID_TO_HRESULT(result_from_vtl1));
    }

    template <typename ReturnT, typename ParamsT>
    ReturnT CallVtl1StubWithResult(void* enclave_instance, std::string_view function_name, ParamsT& function_params)
    {
        std::shared_ptr<ParamsT> heap_tuple = std::make_shared<ParamsT>(function_params);
        EnclaveFunctionContext function_context = SetupVtl1Call<ParamsT>(heap_tuple.get());

        auto module = reinterpret_cast<HMODULE>(enclave_instance);
        auto proc_address = GetProcAddress(module, function_name.data());

        auto routine = reinterpret_cast<PENCLAVE_ROUTINE>(proc_address);
        void* result_from_vtl1;

        THROW_IF_WIN32_BOOL_FALSE(CallEnclave(routine, reinterpret_cast<void*>(&function_context), TRUE, &result_from_vtl1));
        THROW_IF_FAILED(PVOID_TO_HRESULT(result_from_vtl1));
        
        ReturnT return_value = reinterpret_cast<ReturnT>(function_context.m_return_param);

        if (!return_value)
        {
            LOG_IF_NULL_ALLOC_MSG(return_value, "VTL1 function that returns a value returned null.");
        }

        // Return developer must free with HeapFree or vtl0_memory_ptr.
        return return_value;
    }
}
