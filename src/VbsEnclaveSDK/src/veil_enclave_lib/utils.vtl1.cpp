// © Microsoft Corporation. All rights reserved.

#include "pch.h"

#include <array>

#include <bcrypt.h>

#include "utils.vtl1.h"

//#include "shared_enclave.h"
//#include "enclavethreading.h"

inline HRESULT CheckForVTL0Buffer(_In_ const void* const, _In_ const size_t)
{
    // todo: implemented by tooling repo
    return S_OK;
}

inline HRESULT CheckForVTL1Buffer(_In_ const void* const, _In_ const size_t)
{
    // todo: implemented by tooling repo
    return S_OK;
}

#include <wil/enclave/push_disable_wil_logging.h>
HRESULT CopyFromVTL0ToVTL1_NoLogging(
    _Out_writes_bytes_(length) void* const vtl1Destination, _In_reads_bytes_(length) const void* const vtl0Source, _In_ const size_t length)
{
#pragma warning(push)
#pragma warning(disable : 6001) // Suppress warning about uninitialized memory, as CheckForVTL0Buffer/1 don't dereference the first parameter
    RETURN_IF_FAILED_EXPECTED(CheckForVTL0Buffer(vtl0Source, length));
    RETURN_IF_FAILED_EXPECTED(CheckForVTL1Buffer(vtl1Destination, length));
#pragma warning(pop)
    memcpy_s(vtl1Destination, length, vtl0Source, length);
    return S_OK;
}
#include <wil/enclave/pop_enable_wil_logging.h>

HRESULT CopyFromVTL1ToVTL0(
    _Out_writes_bytes_(length) void* const vtl0Destination, _In_reads_bytes_(length) const void* const vtl1Source, _In_ const size_t length)
{

#pragma warning(push)
#pragma warning(disable : 6001) // Suppress warning about uninitialized memory, as CheckForVTL0Buffer/1 don't dereference the first parameter.
    RETURN_IF_FAILED(CheckForVTL1Buffer(vtl1Source, length));
    RETURN_IF_FAILED(CheckForVTL0Buffer(vtl0Destination, length));
#pragma warning(pop)
    memcpy_s(vtl0Destination, length, vtl1Source, length);
    return S_OK;
}

void CopyToVtl0OutputBlob(std::span<uint8_t const> data, AiEnclaveOutputBlob* vtl0Blob)
{
    // Recheck the blob content...
    auto vtl1Blob = CopyFromVTL0ToVTL1<AiEnclaveOutputBlob>(vtl0Blob);

    if (vtl1Blob.Capacity < data.size())
    {
        vtl0Blob->Size = data.size();
        THROW_HR(HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER));
    }
    else if (data.empty())
    {
        vtl0Blob->Size = data.size();
    }
    else
    {
        THROW_IF_FAILED(CopyFromVTL1ToVTL0(vtl1Blob.Data, data.data(), data.size()));
        vtl0Blob->Size = data.size();
    }
}

// Verifies that the output blob is correctly formed. Note that this must be called only on
// AiEnclaveOutputBlob structures that are in VTLT1, pointing to VTL0 data.
void CheckOutputBlob(const AiEnclaveOutputBlob& outputBlob)
{
    // Output blobs can be "all zeros" (meaning all fields empty), or they can have a data _and_
    // a nonzero capacity buffer.  If the data pointer is present with a capacity field,
    // data+capacity must be a valid VTL0 buffer.
    if (outputBlob.Data)
    {
        THROW_HR_IF(E_INVALIDARG, outputBlob.Capacity == 0);
        THROW_HR_IF(E_INVALIDARG, outputBlob.Size != 0);
        THROW_IF_FAILED(CheckForVTL0Buffer(outputBlob.Data, outputBlob.Capacity));
    }
    else
    {
        THROW_HR_IF(E_INVALIDARG, outputBlob.Capacity != 0);
        THROW_HR_IF(E_INVALIDARG, outputBlob.Size != 0);
    }
}

#include <wil/enclave/push_disable_wil_logging.h>
#pragma region WIL logging not allowed (used by logging code)

// Enclave image creation policies
#ifndef ENCLAVE_MAX_THREADS
#define ENCLAVE_MAX_THREADS 16
#endif

uint32_t g_threadEnclaveCalloutCounts[ENCLAVE_MAX_THREADS];

/*
extern uint32_t& GetThreadEnclaveCalloutCount_NoLogging()
{
    auto index = GetCurrentEnclaveThreadIndex();
    FAIL_FAST_IMMEDIATE_IF(index < 0 || index >= ENCLAVE_MAX_THREADS);
    return g_threadEnclaveCalloutCounts[index];
}
*/
#pragma endregion
#include <wil/enclave/pop_enable_wil_logging.h> // WIL logging permitted again


