// © Microsoft Corporation. All rights reserved.

#include "pch.h"

//#include "shared_enclave.h"
//#include "data_enclave.h"

// BCRYPT constants
#define SUPPORT_SHARED_PUBLIC_KEY_ALG_HANDLE BCRYPT_ECDH_P384_ALG_HANDLE
#define SUPPORT_SHARED_DH_KEY_ALG_HANDLE BCRYPT_ECDH_P384_ALG_HANDLE
#define SUPPORT_SHARED_HASH_ALG_HANDLE BCRYPT_SHA256_ALG_HANDLE
#define SUPPORT_SHARED_RNG_ALG_HANDLE BCRYPT_RNG_ALG_HANDLE
#define SUPPORT_SHARED_SYMMETRIC_KEY_ALG_HANDLE BCRYPT_AES_GCM_ALG_HANDLE

constexpr auto SUPPORT_SHARED_PUBLIC_KEY_ALGORITHM = BCRYPT_ECDH_P384_ALGORITHM;
constexpr auto SUPPORT_SHARED_PUBLIC_KEY_BLOB_TYPE = BCRYPT_ECCPUBLIC_BLOB;
constexpr auto SUPPORT_SHARED_PUBLIC_KEY_LENGTH_BYTES = 0x68;  // ECDH P-384
constexpr auto SUPPORT_SHARED_SYMMETRIC_KEY_LENGTH_BYTES = 32; // AES-GCM
constexpr auto SUPPORT_SHARED_DH_KEY_LENGTH_BITS = 384;        // ECDH P-384
constexpr auto SUPPORT_SHARED_TOKEN_SIGNATURE_SIZE_BYTES = 96; // ECDH P-384
constexpr auto SUPPORT_SHARED_HASH_SIZE_BYTES = 32;

namespace veil::vtl1::cypto
{
    HRESULT GetRandomNumber(_In_ ULONG randomByteCount, _Out_writes_bytes_(randomByteCount) PUCHAR random)
    {
        return HRESULT_FROM_NT(BCryptGenRandom(BCRYPT_RNG_ALG_HANDLE, random, randomByteCount, 0));
    }

    HRESULT CreateSymmetricKey(_Out_ BCRYPT_KEY_HANDLE& symmetricKeyHandle)
    {
        UINT8 key[SUPPORT_SHARED_SYMMETRIC_KEY_LENGTH_BYTES];
        RETURN_IF_FAILED(GetRandomNumber(SUPPORT_SHARED_SYMMETRIC_KEY_LENGTH_BYTES, key));

        NTSTATUS status =
            BCryptGenerateSymmetricKey(SUPPORT_SHARED_SYMMETRIC_KEY_ALG_HANDLE, &symmetricKeyHandle, nullptr, 0, key, ARRAYSIZE(key), 0);

        if (!BCRYPT_SUCCESS(status))
        {
            return HRESULT_FROM_NT(status);
        }

        return S_OK;
    }

    HRESULT HashData(_In_reads_bytes_(dataSizeBytes) PUCHAR dataToHash, _In_ ULONG dataSizeBytes, _Out_writes_bytes_(SUPPORT_SHARED_HASH_SIZE_BYTES) PUCHAR hash)
    {
        NTSTATUS status =
            BCryptHash(SUPPORT_SHARED_HASH_ALG_HANDLE, nullptr, 0, dataToHash, dataSizeBytes, hash, SUPPORT_SHARED_HASH_SIZE_BYTES);

        if (!BCRYPT_SUCCESS(status))
        {
            return HRESULT_FROM_NT(status);
        }

        return S_OK;
    }

    HRESULT VerifyHash(_In_reads_bytes_(dataSizeBytes) PUCHAR dataToHash, _In_ ULONG dataSizeBytes, _In_reads_bytes_(SUPPORT_SHARED_HASH_SIZE_BYTES) PUCHAR hash)
    {
        UCHAR computedHash[SUPPORT_SHARED_HASH_SIZE_BYTES];
        HRESULT hr = HashData(dataToHash, dataSizeBytes, computedHash);

        if (FAILED(hr))
        {
            return hr;
        }

        if (memcmp(hash, computedHash, SUPPORT_SHARED_HASH_SIZE_BYTES) != 0)
        {
            hr = HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
        }

        return hr;
    }

    HRESULT LoadPublicKeyHelper(_In_reads_bytes_(publicKeyByteCount) PUCHAR publicKey, _In_ UINT32 publicKeyByteCount, _Out_ BCRYPT_KEY_HANDLE& publicKeyHandle)
    {
        HRESULT hr = S_OK;
        publicKeyHandle = nullptr;
        NTSTATUS status = BCryptImportKeyPair(
            BCRYPT_ECDSA_P384_ALG_HANDLE, NULL, BCRYPT_ECCPUBLIC_BLOB, &publicKeyHandle, publicKey, publicKeyByteCount, 0);

        if (!BCRYPT_SUCCESS(status))
        {
            return HRESULT_FROM_NT(status);
        }

        if (FAILED(hr))
        {
            if (publicKeyHandle != nullptr)
            {
                BCryptDestroyKey(publicKeyHandle);
                publicKeyHandle = nullptr;
            }
        }

        return hr;
    }

    HRESULT VerifyPublicKey(_In_reads_bytes_(publicKeyByteCount) PUCHAR publicKey, _In_ UINT32 publicKeyByteCount)
    {
        // Verify that the public key is valid
        BCRYPT_KEY_HANDLE publicKeyHandle = nullptr;
        HRESULT hr = LoadPublicKeyHelper(publicKey, publicKeyByteCount, publicKeyHandle);

        if (publicKeyHandle != nullptr)
        {
            BCryptDestroyKey(publicKeyHandle);
        }

        return hr;
    }

    HRESULT VerifySignature(
        _In_reads_bytes_(publicKeyByteCount) PUCHAR publicKey,
        _In_ UINT32 publicKeyByteCount,
        _In_reads_bytes_(signedDataByteCount) PUCHAR signedData,
        _In_ UINT32 signedDataByteCount,
        _In_reads_bytes_(signatureByteCount) PUCHAR signature,
        _In_ UINT32 signatureByteCount)
    {
        BCRYPT_KEY_HANDLE publicKeyHandle = nullptr;

        // Load public key
        HRESULT hr = LoadPublicKeyHelper(publicKey, publicKeyByteCount, publicKeyHandle);

        if (FAILED(hr))
        {
            return hr;
        }

        // Verify signature over signedData
        NTSTATUS status =
            BCryptVerifySignature(publicKeyHandle, nullptr, signedData, signedDataByteCount, signature, signatureByteCount, 0);

        if (!BCRYPT_SUCCESS(status))
        {
            hr = HRESULT_FROM_NT(status);
        }

        if (publicKeyHandle != nullptr)
        {
            BCryptDestroyKey(publicKeyHandle);
        }

        return hr;
    }

}
