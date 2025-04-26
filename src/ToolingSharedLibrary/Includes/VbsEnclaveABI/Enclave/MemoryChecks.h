// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once 

// __ENCLAVE_PROJECT__ must be defined inside the enclave project only.
#ifdef __ENCLAVE_PROJECT__

#include <VbsEnclaveABI\Shared\VbsEnclaveAbiBase.h>
#include <winenclaveapi.h>
#include <ntenclv.h>
#include <safeint.h>

namespace VbsEnclaveABI::Enclave::MemoryChecks
{
    inline LPCVOID s_enclave_memory_begin; // inclusive
    inline LPCVOID s_enclave_memory_end;   // exclusive
    inline std::atomic<bool> s_memory_bounds_calculated{};

    inline HRESULT InitializeEnclaveDetails()
    {
        if (!s_memory_bounds_calculated.load(std::memory_order::memory_order_acquire))
        {
            ENCLAVE_INFORMATION enclaveInfo {};
            RETURN_IF_FAILED_EXPECTED(EnclaveGetEnclaveInformation(sizeof(enclaveInfo), &enclaveInfo));

            s_enclave_memory_begin = enclaveInfo.BaseAddress;

            bool memory_end_update_succeeded = msl::utilities::SafeAdd(
                reinterpret_cast<size_t>(s_enclave_memory_begin),
                enclaveInfo.Size,
                *reinterpret_cast<size_t*>(&s_enclave_memory_end));

            // TODO: Add our own Hresult
            RETURN_HR_IF_EXPECTED(E_FAIL, !memory_end_update_succeeded);

            s_memory_bounds_calculated.store(true, std::memory_order::memory_order_release);
        }

        if ((s_enclave_memory_begin == nullptr) || (s_enclave_memory_end == nullptr))
        {
            return E_FAIL; // TODO: Add our own Hresult
        }

        return S_OK;
    }

    inline HRESULT GetEndOfEnclaveMemoryRange(
        _In_ const void* start_of_range,
        _Out_ const void** end_of_range,
        _In_ const size_t length)
    {
        static_assert(sizeof(PVOID) == sizeof(size_t), "Pointer size must equal size_t size.");

        bool end_range_update_succeeded = msl::utilities::SafeAdd(
            reinterpret_cast<size_t>(start_of_range),
            length,
            *reinterpret_cast<size_t*>(end_of_range));

        RETURN_HR_IF_EXPECTED(E_INVALIDARG, !end_range_update_succeeded);

        RETURN_IF_FAILED_EXPECTED(InitializeEnclaveDetails());

        return S_OK;
    }

    inline HRESULT CheckForVTL0Buffer(_In_ const void* buffer, _In_ const size_t length)
    {
        // If there are no bytes in the buffer, then it doesn't matter where the pointer points.
        // The empty set is a subset of every set.
        if (length == 0)
        {
            return S_OK;
        }

        const void* end_of_range = 0; // exclusive
        RETURN_IF_FAILED(GetEndOfEnclaveMemoryRange(buffer, &end_of_range, length));

        // We now have the enclave bounds. Now we simply need to check that no part
        // of the untrusted buffer overlaps with the enclave's secure memory space.
        // n.b. 'begin' is inclusive, 'end' is exclusive, i.e., range is [begin, end).
        if ((end_of_range <= s_enclave_memory_begin) || (buffer >= s_enclave_memory_end))
        {
            return S_OK; 
        }

        return E_FAIL; // TODO: Add our own Hresult
    }

    inline HRESULT CheckForVTL1Buffer(
        _In_ const void* buffer,
        _In_ const size_t length)
    {
        // If there are no bytes in the buffer, then it doesn't matter where the pointer points.
        // The empty set is a subset of every set.
        // This is particularly important because { nullptr, 0 } would otherwise
        // be rejected.
        if (length == 0)
        {
            return S_OK;
        }

        const void* end_of_range = 0; // exclusive
        RETURN_IF_FAILED(GetEndOfEnclaveMemoryRange(buffer, &end_of_range, length));

        // We now have the enclave bounds. Now we simply need to check that the
        // trusted buffer is completely within the enclave's secure memory space.
        // n.b. 'begin' is inclusive, 'end' is exclusive, i.e., range is [begin, end).
        if ((buffer >= s_enclave_memory_begin) && (end_of_range <= s_enclave_memory_end))
        {
            return S_OK;
        }

        return E_FAIL; // TODO: Add our own Hresult
    }

    // Returns S_OK if the function pointer is entirely outside the VTL1 address space.
    inline HRESULT CheckForVTL0Function(_In_ void* (*fn)(void*))
    {
        return CheckForVTL0Buffer(fn, 1);
    }
}

#endif // end __ENCLAVE_PROJECT__
