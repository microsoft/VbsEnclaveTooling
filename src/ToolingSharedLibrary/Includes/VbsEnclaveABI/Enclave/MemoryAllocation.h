// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once 

// __ENCLAVE_PROJECT__ must be defined inside the enclave project only.
#ifdef __ENCLAVE_PROJECT__

#include <VbsEnclaveABI\Shared\VbsEnclaveAbiBase.h>
#include <VbsEnclaveABI\Enclave\MemoryChecks.h>

using namespace VbsEnclaveABI::Enclave::MemoryChecks;

namespace VbsEnclaveABI::Enclave
{
    namespace VTL0CallBackHelpers
    {
        inline LPENCLAVE_ROUTINE s_vtl0_allocation_function;
        inline LPENCLAVE_ROUTINE s_vtl0_deallocation_function;
        inline wil::srwlock s_vtl0_function_table_lock;
        inline bool s_are_functions_registered;
        inline std::unordered_map<std::uint32_t, std::uint64_t> s_vtl0_function_table;
        static constexpr size_t minimum_number_of_callbacks = 2;

        static inline HRESULT AddVtl0FunctionsToTable(_In_ const std::vector<std::uint64_t>& stub_functions)
        {
            auto lock = s_vtl0_function_table_lock.lock_exclusive();

            size_t callbacks_size = stub_functions.size();
            RETURN_HR_IF(E_INVALIDARG, callbacks_size < minimum_number_of_callbacks);

            if (s_are_functions_registered)
            {
                return S_OK;
            }

            // Add in function addresses to map 1 indexed.
            for (auto i = 0U; i < callbacks_size; i++)
            {
                auto vtl0_func = reinterpret_cast<LPENCLAVE_ROUTINE>(stub_functions[i]);
                HRESULT hr = CheckForVTL0Function(vtl0_func);

                if (FAILED_LOG(hr))
                {
                    s_vtl0_function_table.clear();
                    return hr;
                }

                s_vtl0_function_table[i + 1U] = stub_functions[i];
            }

            // first value should always be the allocation function and the second will always
            // be the deallocation function.
            s_vtl0_allocation_function = reinterpret_cast<LPENCLAVE_ROUTINE>(s_vtl0_function_table[1]);
            s_vtl0_deallocation_function = reinterpret_cast<LPENCLAVE_ROUTINE>(s_vtl0_function_table[2]);

            s_are_functions_registered = true;

            return S_OK;
        }
    }

    namespace EnclaveMemoryAllocation
    {
        using namespace VTL0CallBackHelpers;

        template <typename T>
        static inline HRESULT AllocateVtl0Memory(_Out_ T** vtl0_memory, _In_ size_t size)
        {
            *vtl0_memory = nullptr;
            RETURN_HR_IF_NULL_MSG(E_INVALIDARG, s_vtl0_allocation_function, "VTL0 allocation function not registered.");

            void* returned_vtl0_memory;
            RETURN_IF_WIN32_BOOL_FALSE(CallEnclave(
                s_vtl0_allocation_function,
                reinterpret_cast<void*>(size),
                TRUE,
                &returned_vtl0_memory));

            RETURN_IF_NULL_ALLOC(returned_vtl0_memory);
            *vtl0_memory = static_cast<T*>(returned_vtl0_memory);
            return S_OK;
        }

       
        static inline HRESULT DeallocateVtl0Memory(_Inout_ void* vtl0_memory)
        {
            RETURN_HR_IF_NULL_MSG(E_INVALIDARG, s_vtl0_deallocation_function, "VTL0 deallocation function not registered.");
            void* returned_result;
            RETURN_IF_WIN32_BOOL_FALSE(CallEnclave(
                s_vtl0_deallocation_function,
                vtl0_memory,
                TRUE,
                &returned_result));

            RETURN_IF_FAILED(ABI_PVOID_TO_HRESULT(returned_result));

            return S_OK;
        }
    }
} 
#endif // end __ENCLAVE_PROJECT__
