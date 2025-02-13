// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once 

// __ENCLAVE_PROJECT__ must be defined inside the enclave project only. If it is defined
// inside the host, the host won't build as winenclaveapi
// is not compatible in an non enclave environment.
#ifdef __ENCLAVE_PROJECT__

#include <VbsEnclaveABI\Shared\VbsEnclaveAbiBase.h>
#include <VbsEnclaveABI\Enclave\Vtl0Pointers.h>
#include <VbsEnclaveABI\Enclave\MemoryAllocation.h>

using namespace VbsEnclaveABI::Enclave::EnclaveMemoryAllocation;
using namespace VbsEnclaveABI::Enclave::Pointers;
using namespace VbsEnclaveABI::Shared;

// Content of this file should only be used within an enclave.
namespace VbsEnclaveABI::Enclave
{
    // This will only be available in debug mode. Accessor Functions have not been ported to GE_Current yet
    // so these place holders will be used until then. This will mean release mode won't build which
    // should be fine until its ported in Feburary, at which point this entire ifndef block can be removed.
    #ifndef NDEBUG
        // REMOVE WHEN PORTED to GE_Current
        HRESULT static inline
            EnclaveCopyIntoEnclave(
                _Out_writes_bytes_(NumberOfBytes) VOID* EnclaveAddress,
                _In_reads_bytes_(NumberOfBytes) const VOID* UnsecureAddress,
                _In_ SIZE_T NumberOfBytes
            )
        {
            memcpy_s(EnclaveAddress, NumberOfBytes, UnsecureAddress, NumberOfBytes);
            return S_OK;
        }

        // REPLACE WITH REAL FUNCTIONS WHEN PORTED to GE_Current
        HRESULT static inline
            EnclaveCopyOutOfEnclave(
                _Out_writes_bytes_(NumberOfBytes) VOID* UnsecureAddress,
                _In_reads_bytes_(NumberOfBytes) const VOID* EnclaveAddress,
                _In_ SIZE_T NumberOfBytes
            )
        {
            memcpy_s(UnsecureAddress, NumberOfBytes, EnclaveAddress, NumberOfBytes);
            return S_OK;
        }
    #endif

    // Generated ABI export functions in VTL1 call this function as an entry point to calling
    // its associated VTL1 ABI impl function.
    template <typename ParamsT, typename ReturnParamsT, typename FuncImplT>
    static inline HRESULT CallVtl1ExportFromVtl1(
        _In_ void* context,
        _In_ FuncImplT abi_impl_func)
    {
        auto function_context = reinterpret_cast<EnclaveFunctionContext*>(context);
        RETURN_HR_IF_NULL(E_INVALIDARG, function_context);
        auto vtl0_context_ptr = vtl0_ptr<EnclaveFunctionContext>(function_context);
        wil::unique_process_heap_ptr<EnclaveFunctionContext> copied_vtl0_context {
            static_cast<EnclaveFunctionContext*>(AllocateMemory(sizeof(EnclaveFunctionContext)))};
        RETURN_IF_NULL_ALLOC(copied_vtl0_context.get());

        RETURN_IF_FAILED(EnclaveCopyIntoEnclave(
            copied_vtl0_context.get(),
            vtl0_context_ptr.get(),
            sizeof(EnclaveFunctionContext)));
        
        RETURN_HR_IF(E_INVALIDARG, copied_vtl0_context->m_forwarded_parameters.buffer_size != sizeof(ParamsT));

        wil::unique_process_heap_ptr<ParamsT> input_params {
           static_cast<ParamsT*>(AllocateMemory(sizeof(ParamsT)))};
        RETURN_IF_NULL_ALLOC(input_params.get());
        RETURN_IF_FAILED(EnclaveCopyIntoEnclave(
            input_params.get(),
            copied_vtl0_context->m_forwarded_parameters.buffer,
            sizeof(ParamsT)));

        ReturnParamsT* return_params_container {};
        CallAbiImplFunction<ParamsT, ReturnParamsT, FuncImplT>
            (*input_params, &return_params_container, abi_impl_func);

        // Make sure we free the vtl1 memory used for the return param before we leave the
        // function. It also shouldn't be null when after the CallAbiImplFunction function.
        RETURN_HR_IF_NULL(E_INVALIDARG, return_params_container);
        wil::unique_process_heap_ptr<ReturnParamsT> vtl1_returned_parameters_ptr { return_params_container };

        // VTL0 will free this memory.
        ReturnParamsT* vtl1_return_params;
        RETURN_IF_FAILED(AllocateVtl0Memory(&vtl1_return_params, sizeof(ReturnParamsT)));
        RETURN_IF_NULL_ALLOC(vtl1_return_params);
        RETURN_IF_FAILED(EnclaveCopyOutOfEnclave(
            vtl1_return_params,
            return_params_container,
            sizeof(ReturnParamsT)));
        
        vtl0_context_ptr->m_returned_parameters.buffer = vtl1_return_params;
        vtl0_context_ptr->m_returned_parameters.buffer_size = sizeof(ReturnParamsT);

        return S_OK;
    }

    // Abi functions in VTL1 call this function as an entry point to calling
    // its associated VTL0 callback.
    template <typename ParamsT, typename ReturnParamsT>
    static inline HRESULT CallVtl0CallbackFromVtl1(
        _In_ std::uint32_t function_index,
        _In_ ParamsT* params_container,
        _Inout_ FunctionResult<ReturnParamsT>& callback_result)
    {
        bool func_index_in_table = s_vtl0_function_table.contains(function_index);
        RETURN_HR_IF(E_INVALIDARG, !func_index_in_table);

        EnclaveFunctionContext vtl1_outgoing_context {};
        vtl1_outgoing_context.m_forwarded_parameters.buffer = params_container;
        vtl1_outgoing_context.m_forwarded_parameters.buffer_size = sizeof(params_container);

        vtl0_memory_ptr<EnclaveFunctionContext> vtl0_context_ptr;
        RETURN_IF_FAILED(AllocateVtl0Memory(&vtl0_context_ptr, sizeof(EnclaveFunctionContext)));
        RETURN_IF_NULL_ALLOC(vtl0_context_ptr.get());

        RETURN_IF_FAILED(EnclaveCopyOutOfEnclave(
            vtl0_context_ptr.get(),
            &vtl1_outgoing_context,
            sizeof(EnclaveFunctionContext)));

        void* vtl0_output_buffer;
        auto vtl0_callback = reinterpret_cast<LPENCLAVE_ROUTINE>(s_vtl0_function_table.at(function_index));

        RETURN_IF_WIN32_BOOL_FALSE((CallEnclave(
            vtl0_callback,
            reinterpret_cast<void*>(vtl0_context_ptr.get()),
            TRUE,
            &vtl0_output_buffer)));
        RETURN_IF_FAILED(PVOID_TO_HRESULT(vtl0_output_buffer));

        EnclaveFunctionContext vtl1_incoming_context {};
        RETURN_IF_FAILED((EnclaveCopyIntoEnclave(
            &vtl1_incoming_context,
            vtl0_context_ptr.get(),
            sizeof(EnclaveFunctionContext))));

        // Make sure returned params are freed before we leave the function.
        auto vtl0_return_params_ptr = 
            reinterpret_cast<ReturnParamsT*>(vtl1_incoming_context.m_returned_parameters.buffer);

        auto vtl0_return_params = vtl0_memory_ptr<ReturnParamsT>(vtl0_return_params_ptr);
        
        // return parameters should have a value e.g ParameterContainer<SomeType>
        // TODO: should create custom hresult to differentiate from others, here.
        RETURN_HR_IF_NULL(E_INVALIDARG, vtl0_return_params.get());

        wil::unique_process_heap_ptr<ReturnParamsT> vtl1_returned_parameters {
           static_cast<ReturnParamsT*>(AllocateMemory(sizeof(ReturnParamsT)))};
        RETURN_IF_NULL_ALLOC(vtl1_returned_parameters.get());

        RETURN_IF_FAILED(EnclaveCopyIntoEnclave(
            vtl1_returned_parameters.get(),
            vtl0_return_params.get(),
            sizeof(ReturnParamsT)));

        // Should be be freed by the generated code in vtl1.
        callback_result.m_returned_parameters = 
            reinterpret_cast<ReturnParamsT*>(vtl1_returned_parameters.release());
        return S_OK;
    }

    static inline HRESULT RegisterVtl0Callbacks(
        _In_ EnclaveParameters params,
        _Out_ ParameterContainer<HRESULT>** return_params)
    {
        auto callbacks = std::vector<std::uint64_t>(params.buffer_size, 0);

        RETURN_IF_FAILED(EnclaveCopyIntoEnclave(
            callbacks.data(),
            params.buffer,
            sizeof(std::uint64_t) * params.buffer_size));
        
        RETURN_IF_FAILED(AddVtl0FunctionsToTable(callbacks));
        auto result = ParameterContainer<HRESULT>(S_OK);

        // Caller original vtl1 caller will free.
        void* new_return_params_ptr = AllocateMemory(sizeof(result));
        memcpy(new_return_params_ptr, &result, sizeof(result));
        *return_params = reinterpret_cast<ParameterContainer<HRESULT>*>(new_return_params_ptr);

        return S_OK;
    }

    template <typename T>
    inline void PerformVTL0AllocationAndCopy(T** desc, T* src, size_t size)
    {
        if (!src)
        {
            *desc = nullptr;
            return;
        }

        THROW_IF_FAILED(AllocateVtl0Memory(desc, size));
        wil::unique_process_heap_ptr<T> input_params {*desc};
        THROW_IF_FAILED(EnclaveCopyOutOfEnclave(*desc, src, size));
        input_params.release();
    }

    template <typename T>
    inline void PerformVTL0AllocationAndCopy(T** desc, const T* src, size_t size)
    {
        if (!src)
        {
            *desc = nullptr;
            return;
        }

        THROW_IF_FAILED(AllocateVtl0Memory(desc, size));
        wil::unique_process_heap_ptr<T> input_params {*desc};
        THROW_IF_FAILED(EnclaveCopyOutOfEnclave(*desc, src, size));
        input_params.release();
    }

    template <typename T>
    inline void PerformVTL1AllocationAndCopy(T** desc, T* src, size_t size)
    {
        if (!src)
        {
            *desc = nullptr;
            return;
        }

        *desc  = reinterpret_cast<T*>(AllocateMemory(size));
        THROW_IF_FAILED(EnclaveCopyIntoEnclave(*desc, src, size));
    }

    template <typename T>
    static inline void UpdateOutParamPtr(T** assignee, T* value_to_assign, size_t size)
    {
        THROW_IF_NULL_ALLOC(assignee);
        if (!value_to_assign)
        {
            *assignee = value_to_assign;
            return;
        }

        THROW_IF_FAILED(EnclaveCopyIntoEnclave(*assignee, value_to_assign, size));
    }

    template <typename T>
    static inline void UpdateInOutParamPtr(T* assignee, T* value_to_assign, size_t size)
    {
        THROW_IF_NULL_ALLOC(assignee);
        if (!value_to_assign)
        {
            assignee = value_to_assign;
            return;
        }

        THROW_IF_FAILED(EnclaveCopyIntoEnclave(assignee, value_to_assign, size));
    }
}

#endif // end __ENCLAVE_PROJECT__
