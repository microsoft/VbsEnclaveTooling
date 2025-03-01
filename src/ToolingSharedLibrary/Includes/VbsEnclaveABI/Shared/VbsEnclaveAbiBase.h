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
#include <tuple>
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

        std::string ToStdString()
        {
            if (m_char_buffer)
            {
                m_char_buffer[m_string_size] = '\0';
                return std::string(m_char_buffer, m_string_size);
            }

            return {};
        }
    };
    #pragma pack(pop)

    // Used to marshal a wstring into the enclave
    #pragma pack(push, 1)
    struct WEnclaveString
    {
        wchar_t* m_char_buffer;
        size_t m_string_size;

        std::wstring ToStdWstring()
        {
            if (m_char_buffer)
            {
                m_char_buffer[m_string_size] = '\0';
                return std::wstring(m_char_buffer, m_string_size);
            }

            return {};
        }
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
    // This includes in, inout, out parameters. It could also include a functions return
    // value
    #pragma pack(push, 1)
    template <typename... Args>
    struct ParameterContainer
    {
        std::tuple<Args...> m_members;
        ParameterContainer(Args... args) : m_members(std::make_tuple(args...)) {}

        ParameterContainer() = default;
    };
    #pragma pack(pop)

    // Used for functions that do not return parameters/a return value
    #pragma pack(push, 1)
    template <>
    struct ParameterContainer<>
    {
        std::tuple<> m_members;
        ParameterContainer() = default;
    };
    #pragma pack(pop)

    // Used as a container for a functions non pointer InOut/Out parameters
    // and the functions return value.
    // This is created by one side of the trust boundary in a generated
    // abi function and returned to the otherside (original caller).
    // ReturnParamsT is used exclusively as a ParameterContainer but the types
    // are function specific.
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
   
    // Forwards values inside ParamsT's m_member tuple to the generated abi function outlined in 
    // FuncT. This will expand the tuple values and pass them individually like the FuncT would
    // expect.
    template <typename ParamsT, typename ReturnParamsT, typename FuncT, std::size_t... I>
    static inline void CallDeveloperImplFunction(
        _In_ ParamsT&& input_params,
        _In_ ReturnParamsT** return_params,
        _In_ FuncT func,
        _In_ std::index_sequence<I...>)
    {
        // We use ParameterContainer<> when a function call is made across the trust boundary
        // to symbolize no return params needed for the function.
        if constexpr (std::is_same_v<ReturnParamsT, ParameterContainer<>>)
        {
            func((std::get<I>(input_params.m_members))...);
        }
        else
        {
            func((std::get<I>(input_params.m_members))..., return_params);
        }
    }

    // Used by abi functions to call and forward parameters to another abi function. 
    // ParamsT and ReturnParamsT are both ParameterContainer's but each with different
    // templated types depending on the function.
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
        void* allocated_memory = ::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, size);
        LOG_IF_NULL_ALLOC(allocated_memory);
        return allocated_memory;
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
    static inline void UpdateValue(
        _Out_writes_bytes_(number_of_bytes) T* desc,
        _In_reads_bytes_(number_of_bytes) T* src,
        _In_ size_t number_of_bytes)
    {
        memcpy_s(desc, number_of_bytes, src, number_of_bytes);
    }

    template <typename T>
    static inline void UpdateValue(
        _Out_writes_bytes_(number_of_bytes) T* desc,
        _In_reads_bytes_(number_of_bytes) const T* src,
        _In_ size_t number_of_bytes)
    {
        memcpy_s(desc, number_of_bytes, src, number_of_bytes);
    }

    template <typename T>
    inline void PerformAllocationForOutParam(
        _Out_writes_bytes_(number_of_bytes) T*** desc,
        _In_ size_t number_of_bytes)
    {
        *desc = static_cast<T**>(AllocateMemory(number_of_bytes));
        THROW_IF_NULL_ALLOC(*desc);
        **desc = nullptr;
    }

    template <typename T>
    struct HeapDoublePtrDeleter
    {
        void operator()(T** memory) noexcept
        {
            if (memory)
            {
                if (*memory)
                {
                    LOG_IF_FAILED(DeallocateMemory(*memory));
                }

                LOG_IF_FAILED(DeallocateMemory(memory));
            }
        }
    };

    // Specially used internally in the abi generated function for freeing T** values.
    // that it created.
    template <typename T, typename DeleterT = HeapDoublePtrDeleter<T>>
    struct heap_memory_double_ptr
    {
        explicit heap_memory_double_ptr(T** memory) noexcept
            : m_memory(memory)
        {
        }

        ~heap_memory_double_ptr()
        {
            if (m_memory)
            {
                m_deleter(m_memory);
            }
        }

        heap_memory_double_ptr(const heap_memory_double_ptr&) = delete;
        heap_memory_double_ptr& operator=(const heap_memory_double_ptr&) = delete;
        heap_memory_double_ptr& operator=(heap_memory_double_ptr&& other) = delete;
        heap_memory_double_ptr(const heap_memory_double_ptr&& other) = delete;
        private:
            T** m_memory {};
            DeleterT m_deleter {};
    };
}

