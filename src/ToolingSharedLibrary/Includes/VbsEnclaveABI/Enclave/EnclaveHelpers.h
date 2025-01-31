// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once 

// __ENCLAVE_PROJECT__ must be defined inside the enclave project only. If it is defined
// inside the host, the host won't build as winenclaveapi
// is not compatible in an non enclave environment.
// TODO: file missing VTL0 and VTL1 checks from recall
#ifdef __ENCLAVE_PROJECT__

#include <VbsEnclaveABI\Shared\VbsEnclaveAbiBase.h>
#include <VbsEnclaveABI\Shared\VbsEnclaveMemoryHelpers.h>

namespace VbsEnclaveABI
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

    template <typename ParamsT>
    std::tuple<VTL1_EnclaveFunctionContext<ParamsT>, vtl0_ptr<EnclaveFunctionContext>> CopyContextIntoEnclave(void* context)
    {
        auto function_context = reinterpret_cast<EnclaveFunctionContext*>(context);
        THROW_HR_IF_NULL(E_INVALIDARG, function_context);
        auto vtl0_context_ptr = vtl0_ptr<EnclaveFunctionContext>(function_context);
        auto vtl1_context = VTL1_EnclaveFunctionContext<ParamsT>();
        THROW_IF_FAILED(EnclaveCopyIntoEnclave(&(vtl1_context.m_vtl0_context), vtl0_context_ptr.get(), sizeof(EnclaveFunctionContext)));

        // copy in parameters to VTL1 and call developer Impl
        void* params_buffer = vtl1_context.m_vtl0_context.m_parameters.buffer;
        size_t params_buffer_size = vtl1_context.m_vtl0_context.m_parameters.buffer_size;
        ENCLAVE_ALLOC_CALLBACK callback = vtl1_context.m_vtl0_context.allocator.callback;
        THROW_IF_NULL_ALLOC(callback);
        THROW_IF_NULL_ALLOC(params_buffer);
        THROW_HR_IF(E_INVALIDARG, params_buffer_size != sizeof(ParamsT));

        THROW_IF_FAILED(EnclaveCopyIntoEnclave(&(vtl1_context.m_parameters), params_buffer, params_buffer_size));

        return {vtl1_context, vtl0_context_ptr};
    }

    // Note about the verifier, in the future it will be used to do a deep copy of the function
    // parameters, verify then and return them back to this function who will then pass them to
    // the vtl1 impl function. Then when we return we will copy the content of the out params back
    // into the original parameter. For now we simply copy the params into vtl1 and pass them to
    // the impl function.
    template <typename ReturnT, typename ParamsT, typename FuncImplT, typename FuncCopyAndVerifyT>
    static inline HRESULT CallEnclaveFunctionWithResult(void* context, FuncImplT developer_impl_func, FuncCopyAndVerifyT verifier)
    {
        auto [vtl1_context, vtl0_context_ptr] = CopyContextIntoEnclave<ParamsT>(context);

        ReturnT result = CallDeveloperFunctionWrapperWithResult<ReturnT>(vtl1_context.m_parameters, developer_impl_func);
        
        // result is always a pointer
        if (!result)
        {
            // vtl1 returned nullptr. This could be by design, so return early
            return S_OK;
        }

        // Confirm return buffer is null and size is zero. There shouldn't be anything in there until we copy content into it.
        void* return_buffer = vtl1_context.m_vtl0_context.m_return_param;
        size_t return_buffer_size = vtl1_context.m_vtl0_context.m_return_param_size;
        THROW_HR_IF(E_INVALIDARG, return_buffer != nullptr);
        THROW_HR_IF(E_INVALIDARG, return_buffer_size > 0);

        // Vtl0 must free
        void* vtl0_buffer;
        THROW_IF_FAILED(RequestAllocation(vtl1_context.m_vtl0_context.allocator, &vtl0_context_ptr->allocator, sizeof(*result), &vtl0_buffer));

        vtl0_context_ptr->m_return_param_size = sizeof(*result);
        THROW_IF_FAILED(EnclaveCopyOutOfEnclave(vtl0_buffer, &(*result), sizeof(*result)));
        vtl0_context_ptr->m_return_param = vtl0_buffer;

        return S_OK;
    }

    template <typename ParamsT, typename FuncImplT, typename FuncCopyAndVerifyT>
    static inline HRESULT CallEnclaveFunctionNoResult(void* context, FuncImplT developer_impl_func, FuncCopyAndVerifyT verifier)
    {
        auto [vtl1_context, vtl0_context_ptr] = CopyContextIntoEnclave<ParamsT>(context);

        CallDeveloperFunctionWrapperNoResult(vtl1_context.m_parameters, developer_impl_func);

        return S_OK;
    }

    static inline HRESULT RequestAllocation(
        const EnclaveAllocRequest& vtl1_request,
        EnclaveAllocRequest* vtl0_request,
        size_t size, 
        void** allocated)
    {
        void* vtl0_memory = nullptr;
        vtl0_request->size = size;
        THROW_IF_WIN32_BOOL_FALSE(CallEnclave(vtl1_request.callback, vtl0_request, TRUE, &vtl0_memory));
        *allocated = vtl0_memory;
        return S_OK;
    }
}

#endif // end _ENCLAVE_
