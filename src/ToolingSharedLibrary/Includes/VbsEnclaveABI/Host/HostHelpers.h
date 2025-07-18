
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once 
#include <VbsEnclaveABI\Shared\ConversionHelpers.h>
#include <VbsEnclaveABI\Shared\VbsEnclaveAbiBase.h>

// Every function in this file should only be used within the HostApp
namespace VbsEnclaveABI::HostApp
{
    using namespace VbsEnclaveABI::Shared;
    using namespace VbsEnclaveABI::Shared::Converters;

    // VTL0 allocation callback
    inline void* AllocateVtl0MemoryCallback(_In_ void* context)
    {
        auto size = reinterpret_cast<size_t>(context);
        return Shared::AllocateMemory(size);
    }

    // VTL0 deallocation callback
    inline void* DeallocateVtl0MemoryCallback(_In_ void* memory)
    {
        ABI_RETURN_HR_AS_PVOID(Shared::DeallocateMemory(memory));
    }

    // Generated code uses this function to forward input parameters and retrieve
    // return parameters to the developers enclave exported function.
    template <typename ResultT, typename FlatbufferT>
    inline ResultT CallVtl1ExportFromVtl0Impl(
        _In_ const FlatbufferT& flatbuffer_input,
        _In_ void* enclave_instance,
        _In_ std::string_view function_name)
    {
        auto flatbuffer_in_params_builder = PackFlatbuffer(flatbuffer_input);
        EnclaveFunctionContext function_context {};
        function_context.m_forwarded_parameters.buffer = flatbuffer_in_params_builder.GetBufferPointer();
        function_context.m_forwarded_parameters.buffer_size = flatbuffer_in_params_builder.GetSize();
        function_context.m_returned_parameters.buffer = nullptr;
        function_context.m_returned_parameters.buffer_size = 0;

        auto module = reinterpret_cast<HMODULE>(enclave_instance);
        auto proc_address = GetProcAddress(module, function_name.data());
        THROW_LAST_ERROR_IF_NULL(proc_address);

        auto routine = reinterpret_cast<PENCLAVE_ROUTINE>(proc_address);
        void* result_from_vtl1;

        THROW_IF_WIN32_BOOL_FALSE((CallEnclave(
            routine,
            reinterpret_cast<void*>(&function_context),
            TRUE,
            &result_from_vtl1)));
        THROW_IF_FAILED(ABI_PVOID_TO_HRESULT(result_from_vtl1));

        auto return_buffer_size = function_context.m_returned_parameters.buffer_size;
        wil::unique_process_heap_ptr<uint8_t> return_buffer {
            reinterpret_cast<uint8_t*>(function_context.m_returned_parameters.buffer)};
        THROW_HR_IF(E_INVALIDARG, return_buffer_size > 0 && return_buffer.get() == nullptr);

        if constexpr (!std::is_void_v<ResultT>)
        {
            return UnpackFlatbufferWithSize<FlatbufferT>(return_buffer.get(), return_buffer_size);
        }
    }

    template <Structure ResultT, Structure FlatbufferT>
    inline ResultT CallVtl1ExportFromVtl0(
        _In_ const FlatbufferT& flatbuffer_input,
        _In_ void* enclave_instance,
        _In_ std::string_view function_name)
    {
        auto flatbuffer_result = CallVtl1ExportFromVtl0Impl<FlatbufferT>(flatbuffer_input, enclave_instance, function_name);
        return Converters::ConvertStruct<ResultT>(flatbuffer_result);
    }

    template <typename ResultT, Structure InputT>
    requires std::is_void_v<ResultT>
    inline void CallVtl1ExportFromVtl0(
        _In_ const InputT& flatbuffer_input,
        _In_ void* enclave_instance,
        _In_ std::string_view function_name)
    {
        CallVtl1ExportFromVtl0Impl<void>(flatbuffer_input, enclave_instance, function_name);
    }

    // Generated code uses this function to forward input parameters and retrieve
    // return parameters from the the developers vtl0 callback implementation function.
    template <Structure DevTypeT, Structure FlatBufferT, FunctionPtr FuncImplT>
    inline HRESULT CallVtl0CallbackImplFromVtl0(_In_ FuncImplT dev_impl_func, _In_ void* context)
    {
        auto function_context = reinterpret_cast<EnclaveFunctionContext*>(context);
        RETURN_IF_NULL_ALLOC(function_context);
        auto forward_params_buffer = reinterpret_cast<uint8_t*>(function_context->m_forwarded_parameters.buffer);
        size_t forward_params_size = function_context->m_forwarded_parameters.buffer_size;
        RETURN_IF_NULL_ALLOC(forward_params_buffer);
        RETURN_HR_IF(E_INVALIDARG, forward_params_size > 0 && forward_params_buffer == nullptr);

        auto flatbuffer_in_params = UnpackFlatbufferWithSize<FlatBufferT>(forward_params_buffer, forward_params_size);
        auto func_args = Converters::ConvertStruct<DevTypeT>(flatbuffer_in_params);
        
        // Call user implementation
        Converters::CallDevImpl(dev_impl_func, func_args);
        auto flatbuffer_out_params_builder = PackFlatbuffer(Converters::ConvertStruct<FlatBufferT>(func_args));

        // VTL1 frees with vtl0_memory_ptr.
        wil::unique_process_heap_ptr<uint8_t> vtl0_returned_parameters {
           reinterpret_cast<uint8_t*>(AllocateMemory(flatbuffer_out_params_builder.GetSize()))};
        RETURN_IF_NULL_ALLOC(vtl0_returned_parameters.get());
        memcpy_s(
            vtl0_returned_parameters.get(),
            flatbuffer_out_params_builder.GetSize(),
            flatbuffer_out_params_builder.GetBufferPointer(),
            flatbuffer_out_params_builder.GetSize());

        function_context->m_returned_parameters.buffer = vtl0_returned_parameters.get();
        function_context->m_returned_parameters.buffer_size = flatbuffer_out_params_builder.GetSize();

        vtl0_returned_parameters.release();
        return S_OK;
    }
}
