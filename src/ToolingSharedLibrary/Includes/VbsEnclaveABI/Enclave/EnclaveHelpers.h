// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once 

#if !defined(__ENCLAVE_PROJECT__)
#error This header can only be included in an Enclave project (never the HostApp).
#endif

#include <VbsEnclaveABI\Shared\VbsEnclaveAbiBase.h>
#include <VbsEnclaveABI\Enclave\Vtl0Pointers.h>
#include <VbsEnclaveABI\Enclave\MemoryAllocation.h>

using namespace VbsEnclaveABI::Enclave::EnclaveMemoryAllocation;
using namespace VbsEnclaveABI::Enclave::Pointers;
using namespace VbsEnclaveABI::Shared;

// Default all projects consuming VBS Enclave codegen to having restricted memory access enabled.
// See: https://learn.microsoft.com/en-us/windows/win32/api/winenclaveapi/nf-winenclaveapi-enclaverestrictcontainingprocessaccess
#if !defined(ENABLE_ENCLAVE_RESTRICT_CONTAINING_PROCESS_ACCESS)
#define ENABLE_ENCLAVE_RESTRICT_CONTAINING_PROCESS_ACCESS true
#endif

// Content of this file should only be used within an enclave.
namespace VbsEnclaveABI::Enclave
{
    // This will only be available in debug mode. Accessor Functions have not been ported to GE_Current yet
    // so these place holders will be used until then. This will mean release mode won't build which
    // should be fine until its ported in Feburary, at which point this entire ifndef block can be removed.
    #ifdef _DEBUG
        // REMOVE WHEN PORTED to GE_Current
        HRESULT static inline
            EnclaveCopyIntoEnclave(
                _Out_writes_bytes_(NumberOfBytes) VOID* EnclaveAddress,
                _In_reads_bytes_(NumberOfBytes) const VOID* UnsecureAddress,
                _In_ SIZE_T NumberOfBytes
            )
        {
            RETURN_IF_FAILED(CheckForVTL1Buffer(EnclaveAddress, NumberOfBytes));
            RETURN_IF_FAILED(CheckForVTL0Buffer(UnsecureAddress, NumberOfBytes));
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
            RETURN_IF_FAILED(CheckForVTL1Buffer(EnclaveAddress, NumberOfBytes));
            RETURN_IF_FAILED(CheckForVTL0Buffer(UnsecureAddress, NumberOfBytes));
            memcpy_s(UnsecureAddress, NumberOfBytes, EnclaveAddress, NumberOfBytes);
            return S_OK;
        }

        void static inline
            EnableEnclaveRestrictContainingProcessAccessOnce()
        {
            // Do a one-time enablement of process memory restriction setting if module requests it
            // Note: We don't have access to std::call_once
            static std::atomic<bool> s_have_run_once {};
            if (!s_have_run_once.load(std::memory_order_acquire))
            {
                static wil::srwlock s_lock {};
                auto lock = s_lock.lock_exclusive();
                if (!s_have_run_once.load(std::memory_order_relaxed))
                {
                    FAIL_FAST_IF_FAILED(EnableEnclaveRestrictContainingProcessAccess());
                    s_have_run_once.store(true, std::memory_order_release);
                }
            }
        }
    #endif

    // Generated ABI export functions in VTL1 call this function as an entry point to calling
    // its associated VTL1 ABI impl function.
    template <typename ParamsT, typename FuncImplT>
    inline HRESULT CallVtl1ExportFromVtl1(
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
        
        size_t forward_params_size = copied_vtl0_context->m_forwarded_parameters.buffer_size;
        auto forward_params_buffer = copied_vtl0_context->m_forwarded_parameters.buffer;
        RETURN_HR_IF(E_INVALIDARG, forward_params_size > 0 && forward_params_buffer == nullptr);

        wil::unique_process_heap_ptr<std::uint8_t> input_buffer {
           static_cast<std::uint8_t*>(AllocateMemory(forward_params_size))};
        RETURN_IF_NULL_ALLOC(input_buffer.get());
        RETURN_IF_FAILED(EnclaveCopyIntoEnclave(
            input_buffer.get(),
            forward_params_buffer,
            forward_params_size));

        auto flatbuffer_in_params = UnpackFlatbufferWithSize<ParamsT>(input_buffer.get(), forward_params_size);
        flatbuffers::FlatBufferBuilder flatbuffer_out_params_builder {};
        abi_impl_func(flatbuffer_in_params, flatbuffer_out_params_builder);

        // VTL0 will free this memory.
        vtl0_memory_ptr<std::uint8_t> vtl0_return_params;
        RETURN_IF_FAILED(AllocateVtl0Memory(&vtl0_return_params, flatbuffer_out_params_builder.GetSize()));
        RETURN_IF_NULL_ALLOC(vtl0_return_params.get());
        RETURN_IF_FAILED(EnclaveCopyOutOfEnclave(
            vtl0_return_params.get(),
            flatbuffer_out_params_builder.GetBufferPointer(),
            flatbuffer_out_params_builder.GetSize()));

        vtl0_context_ptr->m_returned_parameters.buffer = vtl0_return_params.get();
        vtl0_context_ptr->m_returned_parameters.buffer_size = flatbuffer_out_params_builder.GetSize();
        vtl0_return_params.release();

        return S_OK;
    }

    // Abi functions in VTL1 call this function as an entry point to calling
    // its associated VTL0 callback.
    template <typename ParamsT, typename ReturnParamsT>
    inline HRESULT CallVtl0CallbackFromVtl1(
        _In_ std::string_view function_name,
        _In_ flatbuffers::FlatBufferBuilder& flatbuffer_in_params_builder,
        _Inout_ ReturnParamsT& callback_result)
    {
        LPENCLAVE_ROUTINE vtl0_callback = TryGetFunctionFromVtl0FunctionTable(function_name);
        RETURN_HR_IF_NULL(E_INVALIDARG, vtl0_callback);

        vtl0_memory_ptr<std::uint8_t> vtl0_in_params;
        RETURN_IF_FAILED(AllocateVtl0Memory(&vtl0_in_params, flatbuffer_in_params_builder.GetSize()));
        RETURN_IF_NULL_ALLOC(vtl0_in_params.get());
        RETURN_IF_FAILED(EnclaveCopyOutOfEnclave(
            vtl0_in_params.get(),
            flatbuffer_in_params_builder.GetBufferPointer(),
            flatbuffer_in_params_builder.GetSize()));

        EnclaveFunctionContext vtl1_outgoing_context {};
        vtl1_outgoing_context.m_forwarded_parameters.buffer = vtl0_in_params.get();
        vtl1_outgoing_context.m_forwarded_parameters.buffer_size = flatbuffer_in_params_builder.GetSize();
        vtl1_outgoing_context.m_returned_parameters.buffer = nullptr;
        vtl1_outgoing_context.m_returned_parameters.buffer_size = 0;

        vtl0_memory_ptr<EnclaveFunctionContext> vtl0_context_ptr;
        RETURN_IF_FAILED(AllocateVtl0Memory(&vtl0_context_ptr, sizeof(EnclaveFunctionContext)));
        RETURN_IF_NULL_ALLOC(vtl0_context_ptr.get());

        RETURN_IF_FAILED(EnclaveCopyOutOfEnclave(
            vtl0_context_ptr.get(),
            &vtl1_outgoing_context,
            sizeof(EnclaveFunctionContext)));

        void* vtl0_output_buffer;

        RETURN_IF_WIN32_BOOL_FALSE((CallEnclave(
            vtl0_callback,
            reinterpret_cast<void*>(vtl0_context_ptr.get()),
            TRUE,
            &vtl0_output_buffer)));
        RETURN_IF_FAILED(ABI_PVOID_TO_HRESULT(vtl0_output_buffer));

        EnclaveFunctionContext vtl1_incoming_context {};
        RETURN_IF_FAILED((EnclaveCopyIntoEnclave(
            &vtl1_incoming_context,
            vtl0_context_ptr.get(),
            sizeof(EnclaveFunctionContext))));

        // Make sure returned params are freed before we leave the function.
        auto vtl0_return_params_ptr =
            reinterpret_cast<uint8_t*>(vtl1_incoming_context.m_returned_parameters.buffer);

        auto vtl0_return_params = vtl0_memory_ptr<uint8_t>(vtl0_return_params_ptr);

        // return parameters should have a value e.g ParameterContainer<SomeType>
        // TODO: should create custom hresult to differentiate from others, here.
        RETURN_HR_IF_NULL(E_INVALIDARG, vtl0_return_params.get());

        auto return_buffer_size = vtl1_incoming_context.m_returned_parameters.buffer_size;
        auto return_buffer = vtl1_incoming_context.m_returned_parameters.buffer;
        RETURN_HR_IF(E_INVALIDARG, return_buffer_size > 0 && return_buffer == nullptr);

        wil::unique_process_heap_ptr<uint8_t> vtl1_returned_parameters {
           reinterpret_cast<uint8_t*>(AllocateMemory(return_buffer_size))};
        RETURN_IF_NULL_ALLOC(vtl1_returned_parameters.get());

        RETURN_IF_FAILED(EnclaveCopyIntoEnclave(
            vtl1_returned_parameters.get(),
            vtl0_return_params.get(),
            vtl1_incoming_context.m_returned_parameters.buffer_size));

        callback_result = UnpackFlatbufferWithSize<ReturnParamsT>(vtl1_returned_parameters.get(), return_buffer_size);
        return S_OK;
    }
}
