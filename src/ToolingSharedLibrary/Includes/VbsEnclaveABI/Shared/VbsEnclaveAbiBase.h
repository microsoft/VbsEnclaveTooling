// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once 

// Must be the first header included for enclave dll's
#ifdef __ENCLAVE_PROJECT__
#include <wil/enclave/wil_for_enclaves.h>
#endif

// end

#include <array>
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>
#include <variant>
#include <wil\resource.h>
#include <wil\result_macros.h>

#define HRESULT_TO_PVOID(hr) (PVOID)((ULONG_PTR)(hr) & 0x00000000FFFFFFFF)
#ifndef RETURN_HR_AS_PVOID
#define RETURN_HR_AS_PVOID(hr) return HRESULT_TO_PVOID(hr);
#endif
#define PVOID_TO_HRESULT(p) ((HRESULT)((ULONG_PTR)(p) & 0x00000000FFFFFFFF))
#define RETURN_PVOID_AS_HR(p) return PVOID_TO_HRESULT(p);

// All types and functions within this file should be usable within both the hostApp and the enclave.
namespace VbsEnclaveABI::Shared
{
    // Used to marshal a string into the enclave
    #pragma pack(push, 1)
    struct EnclaveString
    {
        char* m_char_buffer;
        size_t m_string_size;
    };
    #pragma pack(pop)

    #pragma pack(push, 1)
    struct EnclaveParameters
    {
        void* buffer {};
        size_t buffer_size {};
    };
    #pragma pack(pop)

    // Fields in this class are used to copy function parameters
    // and return parameters from one virtual trust layer to the
    // other.
    #pragma pack(push, 1)
    struct EnclaveFunctionContext
    {
        EnclaveParameters m_forwarded_parameters {};

        EnclaveParameters m_returned_parameters {};
    };
    #pragma pack(pop)

    // used to contain all function parameters sent to and from VTL0 and VTL1
    #pragma pack(push, 1)
    template <typename... Args>
    struct ParameterContainer
    {
        std::tuple<Args...> m_members;
        ParameterContainer(Args... args) : m_members(std::make_tuple(args...)) {}

        ParameterContainer() = default;
    };
    #pragma pack(pop)

    #pragma pack(push, 1)
    template <>
    struct ParameterContainer<>
    {
        std::tuple<> m_members;
        ParameterContainer() = default;
    };
    #pragma pack(pop)

    // Used as a container for a functions InOut, Out and return value.
    template <typename ReturnParamsT>
    struct FunctionResult
    {
        ReturnParamsT* m_returned_parameters;

        ~FunctionResult()
        {
            if (m_returned_parameters)
            {
                ::HeapFree(GetProcessHeap(), 0, m_returned_parameters);
            }
        }
    };
   
    template <typename ParamsT, typename ReturnParamsT, typename FuncT, std::size_t... I>
    static inline void CallDeveloperImplFunction(
        _In_ ParamsT&& input_params,
        _In_ ReturnParamsT** return_params,
        _In_ FuncT func,
        _In_ std::index_sequence<I...>)
    {
        // We use ParameterContainer<> to symbolize no return params needed for
        // the function since 'void' is not a type.
        if constexpr (std::is_same_v<ReturnParamsT, ParameterContainer<>>)
        {
            func((std::get<I>(input_params.m_members))...);
        }
        else
        {
            func((std::get<I>(input_params.m_members))..., return_params);
        }
    }

    template <typename ParamsT, typename ReturnParamsT, typename FuncT>
    static inline void CallAbiImplFunction(
        _In_ ParamsT& input_params,
        _In_ ReturnParamsT** return_params,
        _In_ FuncT func)
    {
        constexpr auto size = std::tuple_size<decltype(input_params.m_members)>::value;
        CallDeveloperImplFunction(input_params, return_params, func, std::make_index_sequence<size>{});
    }

    // Used by either vtl0 or vtl1 to allocate their own memory
    static inline void* AllocateMemory(_In_ size_t size)
    {
        return ::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, size);
    }

    // Used by either vtl0 or vtl1 to deallocate their own memory
    static inline HRESULT DeallocateMemory(_In_ void* memory)
    {
        if (memory)
        {
            RETURN_IF_WIN32_BOOL_FALSE(::HeapFree(::GetProcessHeap(), 0, memory));
        }

        return S_OK;
    }

    template <typename T>
    static inline void UpdateValue(T& assignee, T& value_to_assign, size_t size)
    {
        memcpy(&assignee, &value_to_assign, size);
    }
}

