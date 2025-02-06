// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once 

// Must be the first header included for enclave dll's
#ifdef __ENCLAVE_PROJECT__
#include <wil/enclave/wil_for_enclaves.h>
#endif

// end

#include <atomic>
#include <array>
#include <cstdint>
#include <string>
#include <wil\result_macros.h>
#include <optional>
#include <vector>

#define HRESULT_TO_PVOID(hr) (PVOID)((ULONG_PTR)(hr) & 0x00000000FFFFFFFF)
#ifndef RETURN_HR_AS_PVOID
#define RETURN_HR_AS_PVOID(hr) return HRESULT_TO_PVOID(hr);
#endif
#define PVOID_TO_HRESULT(p) ((HRESULT)((ULONG_PTR)(p) & 0x00000000FFFFFFFF))
#define RETURN_PVOID_AS_HR(p) return PVOID_TO_HRESULT(p);

#define ENCLAVE_FUNCTION extern "C" PVOID WINAPI

// All types and functions within this file should be usable within both the hostApp and the enclave.
namespace VbsEnclaveABI
{
    typedef LPENCLAVE_ROUTINE ENCLAVE_ALLOC_CALLBACK;

    #pragma pack(push, 1)
    struct EnclaveAllocRequest
    {
        ENCLAVE_ALLOC_CALLBACK callback {};
        size_t size {};
    };
    #pragma pack(pop)

    #pragma pack(push, 1)
    struct EnclaveString
    {
        char * m_char_buffer;
        size_t m_string_size;
    };
    #pragma pack(pop)

    #pragma pack(push, 1)
    template <typename T>
    struct FunctionParameter
    {
        T m_value {};
    };
    #pragma pack(pop)

    #pragma pack(push, 1)
    struct EnclaveParameters
    {
        void* buffer {};
        size_t buffer_size {};
    };
    #pragma pack(pop)

    // Special type to signal a function has no parameters in the abi layer.
    #pragma pack(push, 1)
    struct __VoidType__
    {
    };
    #pragma pack(pop)

    // Fields in this class are created in VTL0 via the
    // codegen and passed to the enclave via a CallEnclave
    // call.
    #pragma pack(push, 1)
    struct EnclaveFunctionContext
    {
        EnclaveAllocRequest allocator {};

        EnclaveParameters m_parameters {};

        void* m_return_param;

        size_t m_return_param_size{};
    };
    #pragma pack(pop)

    // Fields in this class live in vtl1 and are copied from vtl0
    // using the EnclaveCopyIntoEnclave accessor method.
    template <typename ParamsT>
    struct VTL1_EnclaveFunctionContext
    {
        VTL1_EnclaveFunctionContext() = default;
        VTL1_EnclaveFunctionContext(ParamsT parameters) : m_parameters(parameters){}

        // Used to copy the Vtl0 void* context into vtl1
        EnclaveFunctionContext m_vtl0_context;

        ParamsT m_parameters;
    };

    // used to contain all function parameters sent to and from VTL0 and VTL1
    template <typename... Args>
    struct ParameterContainer
    {
        std::tuple<Args...> m_members;

        ParameterContainer(Args... args) : m_members(std::make_tuple(args...)) {}

        ParameterContainer() = default;
    };

    template <typename ContainerT, typename FuncT, std::size_t... I>
    void CallDeveloperImplFunctionNoResult(ContainerT&& container, FuncT func, std::index_sequence<I...>)
    {
        func((std::get<I>(container.m_members)).m_value...);
    }

    template <typename ReturnT, typename ContainerT, typename FuncT, std::size_t... I>
    ReturnT CallDeveloperImplFunctionWithResult(ContainerT&& container, FuncT func, std::index_sequence<I...>)
    {
        return func((std::get<I>(container.m_members)).m_value...);
    }

    template <typename ContainerT, typename Func>
    void CallDeveloperFunctionWrapperNoResult(const ContainerT& obj, Func func)
    {
        constexpr auto size = std::tuple_size<decltype(obj.m_members)>::value;
        CallDeveloperImplFunctionNoResult(obj, func, std::make_index_sequence<size>{});
    }

    template <typename ReturnT, typename ContainerT, typename Func>
    ReturnT CallDeveloperFunctionWrapperWithResult(const ContainerT& obj, Func func)
    {
        constexpr auto size = std::tuple_size<decltype(obj.m_members)>::value;
        return CallDeveloperImplFunctionWithResult<ReturnT>(obj, func, std::make_index_sequence<size>{});
    }
}
