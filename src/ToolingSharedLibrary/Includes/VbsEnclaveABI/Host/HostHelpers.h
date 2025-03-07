// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once 
#include <VbsEnclaveABI\Shared\VbsEnclaveAbiBase.h>

using namespace VbsEnclaveABI::Shared;

// Every function in this file should only be used within the HostApp
namespace VbsEnclaveABI::HostApp
{
    static inline std::string_view c_register_callbacks_abi_name = "__AbiRegisterVtl0Callbacks__";

    // VTL0 allocation callback
    static inline void* AllocateVtl0MemoryCallback(_In_ void* context)
    {
        auto size = reinterpret_cast<size_t>(context);
        return Shared::AllocateMemory(size);
    }

    // VTL0 deallocation callback
    static inline void* DeallocateVtl0MemoryCallback(_In_ void* memory)
    {
        RETURN_HR_AS_PVOID(Shared::DeallocateMemory(memory));
    }

    // Generated code uses this function to forward input parameters and retrieve
    // return parameters to the developers enclave exported function.
    template <typename ParamsT, typename ReturnParamsT>
    static inline HRESULT CallVtl1ExportFromVtl0(
        _In_ void* enclave_instance,
        _In_ std::string_view function_name,
        _In_ ParamsT& params_container,
        _Inout_ FunctionResult<ReturnParamsT>& return_params)
    {
        EnclaveFunctionContext function_context {};
        function_context.m_forwarded_parameters.buffer = &params_container;
        function_context.m_forwarded_parameters.buffer_size = sizeof(ParamsT);
        function_context.m_returned_parameters.buffer = nullptr;
        function_context.m_returned_parameters.buffer_size = 0;

        auto module = reinterpret_cast<HMODULE>(enclave_instance);
        auto proc_address = GetProcAddress(module, function_name.data());

        auto routine = reinterpret_cast<PENCLAVE_ROUTINE>(proc_address);
        void* result_from_vtl1;

        RETURN_IF_WIN32_BOOL_FALSE((CallEnclave(
            routine, 
            reinterpret_cast<void*>(&function_context),
            TRUE, 
            &result_from_vtl1)));
        RETURN_IF_FAILED(PVOID_TO_HRESULT(result_from_vtl1));

        // return_params will free the memory
        return_params.m_returned_parameters =
            reinterpret_cast<ReturnParamsT*>(function_context.m_returned_parameters.buffer);            

        return S_OK;
    }

    // Generated code uses this function to forward input parameters and retrieve
    // return parameters from the the developers vtl0 callback implementation function.
    template <typename ParamsT, typename ReturnParamsT, typename FuncImplT>
    static inline HRESULT CallVtl0CallbackImplFromVtl0(_In_ void* context, _In_ FuncImplT abi_impl_func)
    {
        auto function_context = reinterpret_cast<EnclaveFunctionContext*>(context);
        RETURN_IF_NULL_ALLOC(function_context);
        auto parameter_container = reinterpret_cast<ParamsT*>(function_context->m_forwarded_parameters.buffer);
        RETURN_IF_NULL_ALLOC(parameter_container);

        // return_params_container is allocated with HeapAlloc by the generated code
        // so vtl1 will have to free.
        ReturnParamsT* return_params_container{};
        CallAbiImplFunction<ParamsT, ReturnParamsT, FuncImplT>
            (*parameter_container, &return_params_container, abi_impl_func);
       
        // VTL1 frees with vtl0_memory_ptr.
        function_context->m_returned_parameters.buffer = return_params_container;
        function_context->m_returned_parameters.buffer_size = sizeof(ReturnParamsT);

        return S_OK;
    }

    template <size_t N>
    HRESULT AbiRegisterVtl0Callbacks(_In_ void* enclave, _In_ std::array<std::uint64_t, N>& callbacks)
    {
        EnclaveParameters parameters{};
        parameters.buffer = &callbacks;
        parameters.buffer_size = N;
        auto container = ParameterContainer<EnclaveParameters>(parameters);

        using ParamsT = decltype(container);
        using ReturnParamsT = ParameterContainer<HRESULT>;
        auto function_result = FunctionResult<ReturnParamsT>();
        RETURN_IF_FAILED((CallVtl1ExportFromVtl0<ParamsT, ReturnParamsT>(
            enclave,
            c_register_callbacks_abi_name,
            container, 
            function_result)));
        
        // There should be only one value in the tuple, our return hresult.
        return std::get<0>(function_result.m_returned_parameters->m_members);
    }
}
