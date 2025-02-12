// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

// Notes: Only callable inside an enclave.
// Return Value: Returns S_OK iff the buffer is entirely outside the VTL1
// address space.
HRESULT CheckForVTL0Buffer_NoLogging(_In_ const void* const pBuffer, _In_ const size_t cbBuffer);

inline HRESULT CheckForVTL0Buffer(_In_ const void* const pBuffer, _In_ const size_t cbBuffer)
{
    return CheckForVTL0Buffer_NoLogging(pBuffer, cbBuffer);
}

// Notes: Only callable inside an enclave.
// Return Value: Returns S_OK iff the buffer is entirely inside the VTL1
// address space.
HRESULT CheckForVTL1Buffer_NoLogging(_In_ const void* const pBuffer, _In_ const size_t cbBuffer);

inline HRESULT CheckForVTL1Buffer(_In_ const void* const pBuffer, _In_ const size_t cbBuffer)
{
    return CheckForVTL1Buffer_NoLogging(pBuffer, cbBuffer);
}

// Notes: Only callable inside an enclave.
// Return Value: Returns S_OK iff the function pointer is entirely outside the
// VTL1 address space.
inline HRESULT CheckForVTL0Function(_In_ void* (*fn)(void*))
{
    return CheckForVTL0Buffer(fn, 1);
}
