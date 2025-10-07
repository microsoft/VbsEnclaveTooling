// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once 

#include <VbsEnclaveABI\Shared\Version.h>

// Version to ensure all translation units are consuming a consistent version of the codegen
#pragma detect_mismatch("__VBS_ENCLAVE_CODEGEN_VERSION__", __VBS_ENCLAVE_CODEGEN_VERSION__)

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
#pragma warning(push)
#pragma warning(disable : 5260) // the constant variable has external\internal linkage:  wistd_functional.h(278,28)
#include <wil\resource.h>
#include <wil\result_macros.h>
#pragma warning(pop)

#include <span>
#undef max // prevent windows max macro from conflicting with flatbuffers macro
#include <flatbuffers/verifier.h>
#include <flatbuffers/flatbuffer_builder.h>

#ifndef ABI_HRESULT_TO_PVOID
#define ABI_HRESULT_TO_PVOID(hr) (PVOID)((ULONG_PTR)(hr) & 0x00000000FFFFFFFF)
#endif

#ifndef ABI_RETURN_HR_AS_PVOID
#define ABI_RETURN_HR_AS_PVOID(hr) return ABI_HRESULT_TO_PVOID(hr);
#endif

#ifndef ABI_PVOID_TO_HRESULT
#define ABI_PVOID_TO_HRESULT(p) ((HRESULT)((ULONG_PTR)(p) & 0x00000000FFFFFFFF))
#endif

#ifndef ABI_RETURN_PVOID_AS_HR
#define ABI_RETURN_PVOID_AS_HR(p) return ABI_PVOID_TO_HRESULT(p);
#endif

// All types and functions within this file should be usable within both the hostApp and the enclave.
namespace VbsEnclaveABI::Shared
{
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

    // Used by either vtl0 or vtl1 to allocate their own memory
    inline void* AllocateMemory(_In_ size_t size)
    {
        void* allocated_memory = ::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, size);
        LOG_IF_NULL_ALLOC(allocated_memory);
        return allocated_memory;
    }

    // Used by either vtl0 or vtl1 to deallocate their own memory
    inline HRESULT DeallocateMemory(_In_ void* memory)
    {
        if (memory)
        {
            RETURN_IF_WIN32_BOOL_FALSE(::HeapFree(::GetProcessHeap(), 0, memory));
        }

        return S_OK;
    }

    // Given a flatbuffer table type, validates the content of a span as being a valid flatbuffer,
    // then unpacks it into the native table type. Throws invalid-argument if the buffer is not
    // valid. Returns default-constructed type if the buffer is empty.
    template <typename T>
    typename T UnpackFlatbuffer(std::span<uint8_t> data)
    {
        if (data.empty())
        {
            return {};
        }
        THROW_HR_IF(E_INVALIDARG, data.size() < sizeof(uint32_t));

        flatbuffers::Verifier verifier(data.data(), data.size());
        using tableType = typename T::TableType;
        auto root = flatbuffers::GetRoot<tableType>(data.data());
        THROW_HR_IF_NULL(E_INVALIDARG, root);
        THROW_HR_IF(E_INVALIDARG, !root->Verify(verifier));

        T table;
        root->UnPackTo(&table);

        return table;
    }

    template <typename T>
    typename T UnpackFlatbufferWithSize(std::uint8_t* data, size_t size)
    {
        return UnpackFlatbuffer<T>(std::span<uint8_t>(data, size));
    }

    constexpr const size_t c_flatbufferInitialDefaultSizeBytes = 4096;

    // Given a flatbuffer table type, packs the native table type into a FlatBufferBuilder
    template <typename T>
    flatbuffers::FlatBufferBuilder PackFlatbuffer(T const& nativeTable)
    {
        using tableType = typename T::TableType;
        flatbuffers::FlatBufferBuilder builder(c_flatbufferInitialDefaultSizeBytes);
        builder.Finish(tableType::Pack(builder, &nativeTable));
        return builder;
    }
}

