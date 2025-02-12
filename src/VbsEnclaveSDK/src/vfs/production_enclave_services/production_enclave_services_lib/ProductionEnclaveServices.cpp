// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "pch.h"

#include "EnclaveServices.h"

class ProductionEnclaveServices : public IEnclaveServices
{
public:
    constexpr ProductionEnclaveServices() = default;

    HRESULT GetAttestationReport(
        _In_opt_ const UINT8 EnclaveData[ENCLAVE_REPORT_DATA_LENGTH],
        _Out_writes_bytes_to_opt_(BufferSize, *OutputSize) PVOID Report,
        _In_ UINT32 BufferSize,
        _Out_ UINT32* OutputSize) override final;

    HRESULT VerifyAttestationReport(_In_ UINT32 EnclaveType, _In_reads_bytes_(ReportSize) const VOID* Report, _In_ UINT32 ReportSize) override final;

    HRESULT SealData(
        _In_reads_bytes_(DataToEncryptSize) const VOID* DataToEncrypt,
        _In_ UINT32 DataToEncryptSize,
        _In_ ENCLAVE_SEALING_IDENTITY_POLICY IdentityPolicy,
        _In_ UINT32 RuntimePolicy,
        _Out_writes_bytes_to_opt_(BufferSize, *ProtectedBlobSize) PVOID ProtectedBlob,
        _In_ UINT32 BufferSize,
        _Out_ UINT32* ProtectedBlobSize) override final;

    HRESULT UnsealData(
        _In_reads_bytes_(ProtectedBlobSize) const VOID* ProtectedBlob,
        _In_ UINT32 ProtectedBlobSize,
        _Out_writes_bytes_to_opt_(BufferSize, *DecryptedDataSize) PVOID DecryptedData,
        _In_ UINT32 BufferSize,
        _Out_ UINT32* DecryptedDataSize,
        _Out_opt_ ENCLAVE_IDENTITY* SealingIdentity,
        _Out_opt_ UINT32* UnsealingFlags) override final;

    HRESULT GetEnclaveInformation(_In_ UINT32 InformationSize, _Out_writes_bytes_(InformationSize) ENCLAVE_INFORMATION* EnclaveInformation) override final;

    BOOLEAN EnclaveUsesAttestedKeys(VOID) override final;

    _Success_(return != FALSE)
    BOOL CallEnclaveImpl(_In_ LPENCLAVE_ROUTINE lpRoutine, _In_ LPVOID lpParameter, _In_ BOOL fWaitForThread, _Out_ LPVOID* lpReturnValue) override final;

    HRESULT EncryptDataForTrustlet(
        _In_reads_bytes_(DataToEncryptSize) const VOID* DataToEncrypt,
        _In_ UINT32 DataToEncryptSize,
        _In_ PTRUSTLET_BINDING_DATA TrustletBindingData,
        _Out_writes_bytes_to_opt_(BufferSize, *EncryptedDataSize) PVOID EncryptedData,
        _In_ UINT32 BufferSize,
        _Out_ UINT32* EncryptedDataSize) override final;
};

_Use_decl_annotations_
HRESULT ProductionEnclaveServices::GetAttestationReport(
    const UINT8 EnclaveData[ENCLAVE_REPORT_DATA_LENGTH],
    PVOID Report,
    UINT32 BufferSize,
    UINT32* OutputSize)
{
    return ::EnclaveGetAttestationReport(EnclaveData, Report, BufferSize, OutputSize);
}

_Use_decl_annotations_
HRESULT ProductionEnclaveServices::VerifyAttestationReport(UINT32 EnclaveType, const VOID* Report, UINT32 ReportSize)
{
    return ::EnclaveVerifyAttestationReport(EnclaveType, Report, ReportSize);
}

_Use_decl_annotations_
HRESULT ProductionEnclaveServices::SealData(
    const VOID* DataToEncrypt,
    UINT32 DataToEncryptSize,
    ENCLAVE_SEALING_IDENTITY_POLICY IdentityPolicy,
    UINT32 RuntimePolicy,
    PVOID ProtectedBlob,
    UINT32 BufferSize,
    UINT32* ProtectedBlobSize)
{
    return ::EnclaveSealData(DataToEncrypt, DataToEncryptSize, IdentityPolicy, RuntimePolicy, ProtectedBlob, BufferSize, ProtectedBlobSize);
}

_Use_decl_annotations_
HRESULT ProductionEnclaveServices::UnsealData(
    const VOID* ProtectedBlob,
    UINT32 ProtectedBlobSize,
    PVOID DecryptedData,
    UINT32 BufferSize,
    UINT32* DecryptedDataSize,
    ENCLAVE_IDENTITY* SealingIdentity,
    UINT32* UnsealingFlags)
{
    return ::EnclaveUnsealData(
        ProtectedBlob, ProtectedBlobSize, DecryptedData, BufferSize, DecryptedDataSize, SealingIdentity, UnsealingFlags);
}

_Use_decl_annotations_
HRESULT ProductionEnclaveServices::GetEnclaveInformation(
    UINT32 InformationSize, ENCLAVE_INFORMATION* EnclaveInformation)
{
    return ::EnclaveGetEnclaveInformation(InformationSize, EnclaveInformation);
}

BOOLEAN ProductionEnclaveServices::EnclaveUsesAttestedKeys(VOID)
{
    return ::EnclaveUsesAttestedKeys();
}

_Use_decl_annotations_
BOOL ProductionEnclaveServices::CallEnclaveImpl(LPENCLAVE_ROUTINE lpRoutine, LPVOID lpParameter, BOOL fWaitForThread, LPVOID* lpReturnValue)
{
    return ::CallEnclave(lpRoutine, lpParameter, fWaitForThread, lpReturnValue);
}

_Use_decl_annotations_
HRESULT ProductionEnclaveServices::EncryptDataForTrustlet(const VOID* DataToEncrypt,
        UINT32 DataToEncryptSize,
        PTRUSTLET_BINDING_DATA TrustletBindingData,
        PVOID EncryptedData,
        UINT32 BufferSize,
        UINT32* EncryptedDataSize)
{
    return ::EnclaveEncryptDataForTrustlet(
        DataToEncrypt, DataToEncryptSize, TrustletBindingData, EncryptedData, BufferSize, EncryptedDataSize);
}

IEnclaveServices& GetEnclaveServices()
{
    static ProductionEnclaveServices s_productionEnclaveServices;

    return s_productionEnclaveServices;
}
