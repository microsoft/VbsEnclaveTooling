// © Microsoft Corporation. All rights reserved.

#include "pch.h"

#include "checks.h"
#include "EnclaveServices.h"

#include <safeint.h>

#include "wil/enclave/push_disable_wil_logging.h"

#ifndef TEST_CODE // Unit tests wil provide their own implementations of these functions

// Shamelessly stolen from os.2020/onecore/windows/attestSql/Attest/common/lib/MemoryUtil.h and stripped down.
// Definitions for static members
namespace details
{
LPCVOID EnclaveMemoryBegin = nullptr; // inclusive
LPCVOID EnclaveMemoryEnd = nullptr;   // exclusive
std::atomic<bool> EnclaveMemoryBoundsCalculated = false;
}; // namespace details

HRESULT InitializeEnclaveDetails()
{
    if (!::details::EnclaveMemoryBoundsCalculated.load(std::memory_order::memory_order_acquire))
    {
        ENCLAVE_INFORMATION enclaveInfo = {0};
        RETURN_IF_FAILED_EXPECTED(GetEnclaveServices().GetEnclaveInformation(sizeof(enclaveInfo), &enclaveInfo));

        ::details::EnclaveMemoryBegin = enclaveInfo.BaseAddress;
        
        /* RETURN_HR_IF_FALSE_EXPECTED(
            E_FAIL,
            msl::utilities::SafeAdd(
                reinterpret_cast<size_t>(::details::EnclaveMemoryBegin),
                enclaveInfo.Size,
                *reinterpret_cast<size_t*>(&::details::EnclaveMemoryEnd))); */
        if (!msl::utilities::SafeAdd(
                reinterpret_cast<size_t>(::details::EnclaveMemoryBegin),
                enclaveInfo.Size,
                *reinterpret_cast<size_t*>(&::details::EnclaveMemoryEnd)))
        {  
            return E_FAIL;
        }

        ::details::EnclaveMemoryBoundsCalculated.store(true, std::memory_order::memory_order_release);
    }

    return ::details::EnclaveMemoryBegin == nullptr || ::details::EnclaveMemoryEnd == nullptr ? E_FAIL : S_OK;
}

/**
 * Determines whether or not buffer pointed to by pBuffer is pointing to VTL0 memory.
 *
 * parameters:
 *
 *      pBuffer  - Start of buffer to validate
 *      cbBuffer - Size of pBuffer in bytes
 *
 * returns:
 *      true if entire buffer pBuffer is in VTL0
 *      false otherwise
 */
HRESULT CheckForVTL0Buffer_NoLogging(_In_ const void* const buffer, _In_ const size_t length)
{
    // If there are no bytes in the buffer, then it doesn't matter where the pointer points.
    // The empty set is a subset of every set.
    if (length == 0)
    {
        return S_OK;
    }

    static_assert(sizeof(PVOID) == sizeof(size_t), "Pointer size must equal size_t size.");

    LPCVOID rangeToCheckBegin = buffer; // inclusive
    LPCVOID rangeToCheckEnd = 0;        // exclusive

    /* RETURN_HR_IF_FALSE_EXPECTED(
        E_INVALIDARG,
        msl::utilities::SafeAdd(reinterpret_cast<size_t>(rangeToCheckBegin), length, *reinterpret_cast<size_t*>(&rangeToCheckEnd))); */
    if (!msl::utilities::SafeAdd(
            reinterpret_cast<size_t>(rangeToCheckBegin), 
            length, 
            *reinterpret_cast<size_t*>(&rangeToCheckEnd)))
    {
        return E_INVALIDARG;
    }

    RETURN_IF_FAILED_EXPECTED(InitializeEnclaveDetails());

    //
    // We now have the enclave bounds. Now we simply need to check that no part
    // of the untrusted buffer overlaps with the enclave's secure memory space.
    // n.b. 'begin' is inclusive, 'end' is exclusive, i.e., range is [begin, end).
    //
    return (rangeToCheckEnd <= ::details::EnclaveMemoryBegin) ||      // range to check is fully before enclave memory
                   (rangeToCheckBegin >= ::details::EnclaveMemoryEnd) // range to check is fully after enclave memory
               ? S_OK
               : E_FAIL;
}

/**
 * Determines whether or not buffer pointed to by pBuffer is pointing to VTL1 memory.
 *
 * parameters:
 *
 *      pBuffer  - Start of buffer to validate
 *      cbBuffer - Size of pBuffer in bytes
 *
 * returns:
 *      true if entire buffer pBuffer is in VTL1
 *      false otherwise
 */
HRESULT CheckForVTL1Buffer_NoLogging(_In_ const void* const buffer, _In_ const size_t length)
{
    // If there are no bytes in the buffer, then it doesn't matter where the pointer points.
    // The empty set is a subset of every set.
    // This is particularly important because { nullptr, 0 } would otherwise
    // be rejected.
    if (length == 0)
    {
        return S_OK;
    }
    static_assert(sizeof(PVOID) == sizeof(size_t), "Pointer size must equal size_t size.");

    LPCVOID rangeToCheckBegin = buffer; // inclusive
    LPCVOID rangeToCheckEnd = 0;        // exclusive

    /* RETURN_HR_IF_FALSE_EXPECTED(
        E_INVALIDARG,
        msl::utilities::SafeAdd(reinterpret_cast<size_t>(rangeToCheckBegin), length, *reinterpret_cast<size_t*>(&rangeToCheckEnd))); */
    if (!msl::utilities::SafeAdd(
            reinterpret_cast<size_t>(rangeToCheckBegin), 
            length, 
            *reinterpret_cast<size_t*>(&rangeToCheckEnd)))
    {
            return E_INVALIDARG;
    }

    RETURN_IF_FAILED_EXPECTED(InitializeEnclaveDetails());

    //
    // We now have the enclave bounds. Now we simply need to check that the
    // trusted buffer is completely within the enclave's secure memory space.
    // n.b. 'begin' is inclusive, 'end' is exclusive, i.e., range is [begin, end).
    //
    return (rangeToCheckBegin >= ::details::EnclaveMemoryBegin)        // range to check is fully after start of enclave memory
                   && (rangeToCheckEnd <= ::details::EnclaveMemoryEnd) // range to check is fully before end of enclave memory
               ? S_OK
               : E_FAIL;
}
#endif
