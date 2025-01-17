// © Microsoft Corporation. All rights reserved.

#pragma once

namespace veil::vtl1::cypto
{
    HRESULT GetRandomNumber(_In_ ULONG randomByteCount, _Out_writes_bytes_(randomByteCount) PUCHAR random);
    HRESULT CreateSymmetricKey(_Out_ BCRYPT_KEY_HANDLE& symmetricKeyHandle);
    HRESULT HashData(
        _In_reads_bytes_(dataSizeBytes) PUCHAR dataToHash,
        _In_ ULONG dataSizeBytes,
        _Out_writes_bytes_(SUPPORT_SHARED_HASH_SIZE_BYTES) PUCHAR hash);
    HRESULT VerifyHash(
        _In_reads_bytes_(dataSizeBytes) PUCHAR dataToHash, _In_ ULONG dataSizeBytes, _In_reads_bytes_(SUPPORT_SHARED_HASH_SIZE_BYTES) PUCHAR hash);
    HRESULT VerifyPublicKey(_In_reads_bytes_(publicKeyByteCount) PUCHAR publicKey, _In_ UINT32 publicKeyByteCount);
    HRESULT VerifySignature(
        _In_reads_bytes_(publicKeyByteCount) PUCHAR publicKey,
        _In_ UINT32 publicKeyByteCount,
        _In_reads_bytes_(signedDataByteCount) PUCHAR signedData,
        _In_ UINT32 signedDataByteCount,
        _In_reads_bytes_(signatureByteCount) PUCHAR signature,
        _In_ UINT32 signatureByteCount);
}
