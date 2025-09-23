// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once 

#include <wil\enclave\wil_for_enclaves.h>
#include <VbsEnclaveABI\Enclave\MemoryAllocation.h>
#include <VbsEnclaveABI\Enclave\Vtl0Pointers.h>
#include <VbsEnclaveABI\Shared\ConversionHelpers.h>
#include <VbsEnclaveABI\Shared\VbsEnclaveAbiBase.h>
#include <VbsEnclaveABI\Shared\Version.h>

// Version to ensure all translation units are consuming a consistent version of the codegen
#pragma detect_mismatch("__VBS_ENCLAVE_CODEGEN_VERSION__", __VBS_ENCLAVE_CODEGEN_VERSION__)

// Default all projects consuming VBS Enclave codegen to having restricted memory access enabled.
// See: https://learn.microsoft.com/en-us/windows/win32/api/winenclaveapi/nf-winenclaveapi-enclaverestrictcontainingprocessaccess
#if !defined(ENABLE_ENCLAVE_RESTRICT_CONTAINING_PROCESS_ACCESS)
#if defined(_DEBUG)
// Keep strict memory disabled for _DEBUG builds to workaround memory access issues in vertdll.dll
#define ENABLE_ENCLAVE_RESTRICT_CONTAINING_PROCESS_ACCESS false
#else
#define ENABLE_ENCLAVE_RESTRICT_CONTAINING_PROCESS_ACCESS true
#endif
#endif

// Content of this file should only be used within an enclave.
namespace VbsEnclaveABI::Enclave
{
    using namespace VbsEnclaveABI::Enclave::EnclaveMemoryAllocation;
    using namespace VbsEnclaveABI::Enclave::Pointers;
    using namespace VbsEnclaveABI::Shared;
    using namespace VbsEnclaveABI::Shared::Converters;

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

    // Generated ABI export functions in VTL1 call this function as an entry point to calling
    // its associated VTL1 ABI impl function.
    template <Structure DevTypeT, Structure FlatBufferT, FunctionPtr FuncImplT>
    inline HRESULT CallVtl1ExportFromVtl1(_In_ FuncImplT dev_impl_func, _In_ void* context)
    {
        auto function_context = reinterpret_cast<EnclaveFunctionContext*>(context);
        RETURN_HR_IF_NULL(E_INVALIDARG, function_context);
        auto vtl0_context_ptr = vtl0_ptr<EnclaveFunctionContext>(function_context);
        EnclaveFunctionContext copied_vtl0_context {};
        RETURN_IF_FAILED(EnclaveCopyIntoEnclave(
            &copied_vtl0_context,
            vtl0_context_ptr.get(),
            sizeof(EnclaveFunctionContext)));
        
        size_t forward_params_size = copied_vtl0_context.m_forwarded_parameters.buffer_size;
        auto forward_params_buffer = copied_vtl0_context.m_forwarded_parameters.buffer;
        RETURN_HR_IF(E_INVALIDARG, forward_params_size > 0 && forward_params_buffer == nullptr);

        wil::unique_process_heap_ptr<std::uint8_t> input_buffer {
           static_cast<std::uint8_t*>(AllocateMemory(forward_params_size))};
        RETURN_IF_NULL_ALLOC(input_buffer.get());
        RETURN_IF_FAILED(EnclaveCopyIntoEnclave(
            input_buffer.get(),
            forward_params_buffer,
            forward_params_size));

        auto flatbuffer_in_params = UnpackFlatbufferWithSize<FlatBufferT>(input_buffer.get(), forward_params_size);
        auto func_args = Converters::ConvertStruct<DevTypeT>(flatbuffer_in_params);

        // Call user implementation
        Converters::CallDevImpl(dev_impl_func, func_args);
        auto flatbuffer_out_params_builder = PackFlatbuffer(Converters::ConvertStruct<FlatBufferT>(func_args));

        // Copy the return flatbuffer data (VTL0 will free this memory)
        vtl0_memory_ptr<std::uint8_t> vtl0_return_params;
        RETURN_IF_FAILED(AllocateVtl0Memory(&vtl0_return_params, flatbuffer_out_params_builder.GetSize()));
        RETURN_IF_NULL_ALLOC(vtl0_return_params.get());
        RETURN_IF_FAILED(EnclaveCopyOutOfEnclave(
            vtl0_return_params.get(),
            flatbuffer_out_params_builder.GetBufferPointer(),
            flatbuffer_out_params_builder.GetSize()));

        auto buffer = vtl0_return_params.get();
        auto bufferSize = flatbuffer_out_params_builder.GetSize();

        // Copy the return flatbuffer pointer & size (into the vtl0 function_context)
        RETURN_IF_FAILED(EnclaveCopyOutOfEnclave(
            &vtl0_context_ptr->m_returned_parameters.buffer_size,
            &bufferSize,
            sizeof(bufferSize)));
        RETURN_IF_FAILED(EnclaveCopyOutOfEnclave(
            &vtl0_context_ptr->m_returned_parameters.buffer,
            &buffer,
            sizeof(buffer)));

        vtl0_return_params.release();

        return S_OK;
    }

    // Abi functions in VTL1 call this function as an entry point to calling
    // its associated VTL0 callback.
    template <typename ResultT, Structure FlatbufferT>
    inline ResultT CallVtl0CallbackFromVtl1Impl(_In_ FlatbufferT flatbuffer_input, _In_ std::string_view function_name)
    {
        LPENCLAVE_ROUTINE vtl0_callback = TryGetFunctionFromVtl0FunctionTable(function_name);
        THROW_HR_IF_NULL(E_INVALIDARG, vtl0_callback);

        auto flatbuffer_in_params_builder = PackFlatbuffer(flatbuffer_input);
        vtl0_memory_ptr<std::uint8_t> vtl0_in_params;
        THROW_IF_FAILED(AllocateVtl0Memory(&vtl0_in_params, flatbuffer_in_params_builder.GetSize()));
        THROW_IF_NULL_ALLOC(vtl0_in_params.get());
        THROW_IF_FAILED(EnclaveCopyOutOfEnclave(
            vtl0_in_params.get(),
            flatbuffer_in_params_builder.GetBufferPointer(),
            flatbuffer_in_params_builder.GetSize()));

        EnclaveFunctionContext vtl1_outgoing_context {};
        vtl1_outgoing_context.m_forwarded_parameters.buffer = vtl0_in_params.get();
        vtl1_outgoing_context.m_forwarded_parameters.buffer_size = flatbuffer_in_params_builder.GetSize();
        vtl1_outgoing_context.m_returned_parameters.buffer = nullptr;
        vtl1_outgoing_context.m_returned_parameters.buffer_size = 0;

        vtl0_memory_ptr<EnclaveFunctionContext> vtl0_context_ptr;
        THROW_IF_FAILED(AllocateVtl0Memory(&vtl0_context_ptr, sizeof(EnclaveFunctionContext)));
        THROW_IF_NULL_ALLOC(vtl0_context_ptr.get());

        THROW_IF_FAILED(EnclaveCopyOutOfEnclave(
            vtl0_context_ptr.get(),
            &vtl1_outgoing_context,
            sizeof(EnclaveFunctionContext)));

        void* vtl0_output_buffer;

        THROW_IF_WIN32_BOOL_FALSE((CallEnclave(
            vtl0_callback,
            reinterpret_cast<void*>(vtl0_context_ptr.get()),
            TRUE,
            &vtl0_output_buffer)));
        THROW_IF_FAILED(ABI_PVOID_TO_HRESULT(vtl0_output_buffer));

        EnclaveFunctionContext vtl1_incoming_context {};
        THROW_IF_FAILED((EnclaveCopyIntoEnclave(
            &vtl1_incoming_context,
            vtl0_context_ptr.get(),
            sizeof(EnclaveFunctionContext))));

        // Make sure returned params are freed before we leave the function.
        auto vtl0_return_params_ptr =
            reinterpret_cast<uint8_t*>(vtl1_incoming_context.m_returned_parameters.buffer);

        auto vtl0_return_params = vtl0_memory_ptr<uint8_t>(vtl0_return_params_ptr);

        // return parameters should have a value e.g ParameterContainer<SomeType>
        // TODO: should create custom hresult to differentiate from others, here.
        THROW_HR_IF_NULL(E_INVALIDARG, vtl0_return_params.get());

        auto return_buffer_size = vtl1_incoming_context.m_returned_parameters.buffer_size;
        auto return_buffer = vtl1_incoming_context.m_returned_parameters.buffer;
        THROW_HR_IF(E_INVALIDARG, return_buffer_size > 0 && return_buffer == nullptr);

        wil::unique_process_heap_ptr<uint8_t> vtl1_returned_parameters {
           reinterpret_cast<uint8_t*>(AllocateMemory(return_buffer_size))};
        THROW_IF_NULL_ALLOC(vtl1_returned_parameters.get());

        THROW_IF_FAILED(EnclaveCopyIntoEnclave(
            vtl1_returned_parameters.get(),
            vtl0_return_params.get(),
            vtl1_incoming_context.m_returned_parameters.buffer_size));

        if constexpr (!std::is_void_v<ResultT>)
        {
            return UnpackFlatbufferWithSize<FlatbufferT>(vtl1_returned_parameters.get(), return_buffer_size);
        }
    }

    template <Structure ResultT, Structure FlatbufferT>
    inline ResultT CallVtl0CallbackFromVtl1(_In_ const FlatbufferT& flatbuffer_input, _In_ std::string_view function_name)
    {
        auto flatbuffer_result = CallVtl0CallbackFromVtl1Impl<FlatbufferT>(flatbuffer_input, function_name);
        return Converters::ConvertStruct<ResultT>(flatbuffer_result);
    }

    template <typename ResultT, Structure FlatbufferT>
    requires std::is_void_v<ResultT>
    inline void CallVtl0CallbackFromVtl1(_In_ const FlatbufferT& flatbuffer_input, _In_ std::string_view function_name)
    {
        CallVtl0CallbackFromVtl1Impl<void>(flatbuffer_input, function_name);
    }

    inline HRESULT RegisterVtl0Callbacks(const std::vector<std::uint64_t>& callback_addresses, const std::vector<std::string>& callback_names)
    {
        RETURN_IF_FAILED(AddVtl0FunctionsToTable(callback_addresses, callback_names));
        return S_OK;  
    }
}
