// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once 

#if !defined(__ENCLAVE_PROJECT__)
#error This header can only be included in an Enclave project (never the HostApp).
#endif

#include <VbsEnclaveABI\Shared\VbsEnclaveAbiBase.h>
#include <VbsEnclaveABI\Enclave\MemoryChecks.h>

namespace VbsEnclaveABI::Enclave
{
    namespace VTL0CallBackHelpers
    {
        using namespace VbsEnclaveABI::Enclave::MemoryChecks;

        inline LPENCLAVE_ROUTINE s_vtl0_allocation_function;
        inline LPENCLAVE_ROUTINE s_vtl0_deallocation_function;
        inline wil::srwlock s_vtl0_function_table_lock{};
        inline std::unordered_map<std::string, std::uintptr_t> s_vtl0_function_table{};
        inline constexpr size_t minimum_number_of_callbacks = 2;
        inline constexpr std::string_view abi_mem_allocation_name = "VbsEnclaveABI::HostApp::AllocateVtl0MemoryCallback";
        inline constexpr std::string_view abi_mem_deallocation_name = "VbsEnclaveABI::HostApp::DeallocateVtl0MemoryCallback";

        inline LPENCLAVE_ROUTINE TryGetFunctionFromVtl0FunctionTable(std::string_view function_name)
        {
            auto lock = s_vtl0_function_table_lock.lock_shared();
            auto iterator = s_vtl0_function_table.find(function_name.data());

            if (iterator == s_vtl0_function_table.end())
            {
                return nullptr;
            }

            return reinterpret_cast<LPENCLAVE_ROUTINE>(iterator->second);
        }

        inline HRESULT AddVtl0FunctionsToTable(
            _In_ const std::vector<std::uintptr_t>& stub_function_addresses,
            _In_ const std::vector<std::string>& stub_function_names)
        {
            auto lock = s_vtl0_function_table_lock.lock_exclusive();

            size_t callbacks_size = stub_function_addresses.size();
            RETURN_HR_IF(E_INVALIDARG, callbacks_size < minimum_number_of_callbacks);
            RETURN_HR_IF(E_INVALIDARG, (stub_function_addresses.size() != stub_function_names.size()));

            for (auto i = 0U; i < callbacks_size; i++)
            {
                auto& function_name = stub_function_names[i];

                if (s_vtl0_function_table.contains(function_name))
                {
                    continue;
                }

                auto vtl0_func = reinterpret_cast<LPENCLAVE_ROUTINE>(stub_function_addresses[i]);
                HRESULT hr = AbiCheckForVTL0Function(vtl0_func);

                if (FAILED_LOG(hr))
                {
                    s_vtl0_function_table.clear();
                    return hr;
                }

                s_vtl0_function_table.emplace(function_name, stub_function_addresses[i]);
            }

            if (!s_vtl0_allocation_function)
            {
                RETURN_HR_IF(E_INVALIDARG, !s_vtl0_function_table.contains(abi_mem_allocation_name.data()));
                s_vtl0_allocation_function = reinterpret_cast<LPENCLAVE_ROUTINE>(s_vtl0_function_table[abi_mem_allocation_name.data()]);
            }

            if (!s_vtl0_deallocation_function)
            {
                RETURN_HR_IF(E_INVALIDARG, !s_vtl0_function_table.contains(abi_mem_deallocation_name.data()));
                s_vtl0_deallocation_function = reinterpret_cast<LPENCLAVE_ROUTINE>(s_vtl0_function_table[abi_mem_deallocation_name.data()]);
            }

            return S_OK;
        }
    }

    namespace EnclaveMemoryAllocation
    {
        using namespace VTL0CallBackHelpers;

        template <typename T>
        inline HRESULT AllocateVtl0Memory(_Out_ T** vtl0_memory, _In_ size_t size)
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

       
        inline HRESULT DeallocateVtl0Memory(_Inout_ void* vtl0_memory)
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
