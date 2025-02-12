// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <ntenclv.h>
#include <enclaveium.h>

// RAII type for managing the enclave callout count.
extern uint32_t& GetThreadEnclaveCalloutCount_NoLogging();
struct enclave_callout
{
    enclave_callout()
    {
        ++m_counter;
    }
    ~enclave_callout()
    {
        --m_counter;
    }

    // Non-copyable, non-movable.
    enclave_callout(enclave_callout const&) = delete;
    void operator=(enclave_callout const&) = delete;

    uint32_t& m_counter = GetThreadEnclaveCalloutCount_NoLogging();
};

struct IEnclaveServices
{
    virtual HRESULT GetAttestationReport(
        _In_opt_ const UINT8 EnclaveData[ENCLAVE_REPORT_DATA_LENGTH],
        _Out_writes_bytes_to_opt_(BufferSize, *OutputSize) PVOID Report,
        _In_ UINT32 BufferSize,
        _Out_ UINT32* OutputSize) = 0;

    virtual HRESULT VerifyAttestationReport(_In_ UINT32 EnclaveType, _In_reads_bytes_(ReportSize) const VOID* Report, _In_ UINT32 ReportSize) = 0;

    virtual HRESULT SealData(
        _In_reads_bytes_(DataToEncryptSize) const VOID* DataToEncrypt,
        _In_ UINT32 DataToEncryptSize,
        _In_ ENCLAVE_SEALING_IDENTITY_POLICY IdentityPolicy,
        _In_ UINT32 RuntimePolicy,
        _Out_writes_bytes_to_opt_(BufferSize, *ProtectedBlobSize) PVOID ProtectedBlob,
        _In_ UINT32 BufferSize,
        _Out_ UINT32* ProtectedBlobSize) = 0;

    virtual HRESULT UnsealData(
        _In_reads_bytes_(ProtectedBlobSize) const VOID* ProtectedBlob,
        _In_ UINT32 ProtectedBlobSize,
        _Out_writes_bytes_to_opt_(BufferSize, *DecryptedDataSize) PVOID DecryptedData,
        _In_ UINT32 BufferSize,
        _Out_ UINT32* DecryptedDataSize,
        _Out_opt_ ENCLAVE_IDENTITY* SealingIdentity,
        _Out_opt_ UINT32* UnsealingFlags) = 0;

    virtual HRESULT GetEnclaveInformation(
        _In_ UINT32 InformationSize, _Out_writes_bytes_(InformationSize) ENCLAVE_INFORMATION* EnclaveInformation) = 0;

    virtual BOOLEAN EnclaveUsesAttestedKeys(VOID) = 0;

    // Wrapper around "VTL1 to VTL0 callouts" so we can keep track of when an outbound enclave call is active
    _Success_(return != FALSE)
    BOOL CallEnclave(_In_ LPENCLAVE_ROUTINE lpRoutine, _In_ LPVOID lpParameter, _In_ BOOL fWaitForThread, _Out_ LPVOID* lpReturnValue)
    {
        enclave_callout callout;
        return this->CallEnclaveImpl(lpRoutine, lpParameter, fWaitForThread, lpReturnValue);
    }

    _Success_(return != FALSE)
    virtual BOOL CallEnclaveImpl(
        _In_ LPENCLAVE_ROUTINE lpRoutine, _In_ LPVOID lpParameter, _In_ BOOL fWaitForThread, _Out_ LPVOID* lpReturnValue) = 0;

    virtual HRESULT EncryptDataForTrustlet(
        _In_reads_bytes_(DataToEncryptSize) const VOID* DataToEncrypt,
        _In_ UINT32 DataToEncryptSize,
        _In_ PTRUSTLET_BINDING_DATA TrustletBindingData,
        _Out_writes_bytes_to_opt_(BufferSize, *EncryptedDataSize) PVOID EncryptedData,
        _In_ UINT32 BufferSize,
        _Out_ UINT32* EncryptedDataSize) = 0;

protected:
    ~IEnclaveServices() = default;
};

/// <summary>
/// Returns an implementation of <see cref="IEnclaveServices" /> that calls into the Windows APIs.
/// </summary>
/// <returns>An instance of <see cref="IEnclaveServices" /> that calls into the Windows APIs</returns>
IEnclaveServices& GetEnclaveServices();

