// © Microsoft Corporation. All rights reserved.

#include "pch.h"

#include <minmax.h>

#include "paramvalidation.vtl1.h"
#include "utils.vtl1.h"

#include "veil_arguments.any.h"

// Phase 2 - Recall key creation and retrieval enclave entry points
#define NGC_CHALLENGE_LENGTH_BYTES 72

// Validation functions
HRESULT VerifyStartHelloSessionParameters(
    _In_ const veil::any::implementation::args::StartHelloSession* params, _Inout_ veil::any::implementation::args::StartHelloSession& startCreateOrLoadRecallKey)
{
    RETURN_HR_IF_NULL(E_INVALIDARG, params);
    RETURN_IF_FAILED(CopyFromVTL0ToVTL1(&startCreateOrLoadRecallKey, params));

    //RETURN_IF_FAILED(VerifySupportedKeyUsage(startCreateOrLoadRecallKey.keyUsage));
    //RETURN_HR(HRESULT(startCreateOrLoadRecallKey.challengeByteCount + 0x80000000));

    RETURN_HR_IF(E_INVALIDARG, startCreateOrLoadRecallKey.challengeByteCount != NGC_CHALLENGE_LENGTH_BYTES);
    RETURN_HR_IF_NULL(E_INVALIDARG, startCreateOrLoadRecallKey.challenge);

    wil::unique_process_heap_ptr<UINT8> challenge{
        static_cast<PUINT8>(HeapAlloc(GetProcessHeap(), 0, startCreateOrLoadRecallKey.challengeByteCount))};
    RETURN_IF_NULL_ALLOC(challenge);

    RETURN_IF_FAILED(
        CopyFromVTL0ToVTL1(challenge.get(), startCreateOrLoadRecallKey.challenge, startCreateOrLoadRecallKey.challengeByteCount));
    startCreateOrLoadRecallKey.challenge = challenge.release();

    return S_OK;
}

HRESULT VerifyGenerateEncryptionKeySecuredByHelloParameters(_In_ const veil::any::implementation::args::GenerateEncryptionKeySecuredByHello* params, _Inout_ veil::any::implementation::args::GenerateEncryptionKeySecuredByHello& finishCreateRecallKey)
{
    RETURN_HR_IF_NULL(E_INVALIDARG, params);
    RETURN_IF_FAILED(CopyFromVTL0ToVTL1(&finishCreateRecallKey, params));

    //RETURN_IF_FAILED(VerifySupportedKeyUsage(finishCreateRecallKey.keyUsage));

    // Validate the ecdhPublicKey buffer
    RETURN_HR_IF(E_INVALIDARG, finishCreateRecallKey.ecdhPublicKey == nullptr && finishCreateRecallKey.ecdhPublicKeyByteCount != 0);
    RETURN_HR_IF(E_INVALIDARG, finishCreateRecallKey.ecdhPublicKey != nullptr && finishCreateRecallKey.ecdhPublicKeyByteCount == 0);

    // Validate the sealedEncryptedRecallKey buffer
    RETURN_HR_IF(
        E_INVALIDARG,
        finishCreateRecallKey.sealedEncryptedRecallKey == nullptr && finishCreateRecallKey.sealedEncryptedRecallKeyByteCount != 0);
    RETURN_HR_IF(
        E_INVALIDARG,
        finishCreateRecallKey.sealedEncryptedRecallKey != nullptr && finishCreateRecallKey.sealedEncryptedRecallKeyByteCount == 0);

    // Validate the encryptedIsSecureIdOwnerId
    RETURN_HR_IF(E_INVALIDARG, finishCreateRecallKey.encryptedIsSecureIdOwnerIdByteCount == 0);
    RETURN_HR_IF_NULL(E_INVALIDARG, finishCreateRecallKey.encryptedIsSecureIdOwnerId);

    // Validate the encryptedCacheConfig
    RETURN_HR_IF(E_INVALIDARG, finishCreateRecallKey.encryptedCacheConfigByteCount == 0);
    RETURN_HR_IF_NULL(E_INVALIDARG, finishCreateRecallKey.encryptedCacheConfig);

    // Validate the encryptedPublicKey
    RETURN_HR_IF(E_INVALIDARG, finishCreateRecallKey.encryptedPublicKeyByteCount == 0);
    RETURN_HR_IF_NULL(E_INVALIDARG, finishCreateRecallKey.encryptedPublicKey);

    wil::unique_process_heap_ptr<void> encryptedIsSecureIdOwnerId;
    wil::unique_process_heap_ptr<void> encryptedCacheConfig;
    wil::unique_process_heap_ptr<void> encryptedPublicKey;

    auto cleanup = wil::scope_exit([&]
    {
        if (encryptedIsSecureIdOwnerId)
        {
            SecureZeroMemory(encryptedIsSecureIdOwnerId.get(), finishCreateRecallKey.encryptedIsSecureIdOwnerIdByteCount);
        }

        if (encryptedCacheConfig)
        {
            SecureZeroMemory(encryptedCacheConfig.get(), finishCreateRecallKey.encryptedCacheConfigByteCount);
        }

        if (encryptedPublicKey)
        {
            SecureZeroMemory(encryptedPublicKey.get(), finishCreateRecallKey.encryptedPublicKeyByteCount);
        }
    });

    // Copy the encryptedIsSecureIdOwnerId from VTL0 to VTL1
    encryptedIsSecureIdOwnerId.reset(HeapAlloc(GetProcessHeap(), 0, finishCreateRecallKey.encryptedIsSecureIdOwnerIdByteCount));
    RETURN_IF_NULL_ALLOC(encryptedIsSecureIdOwnerId);

    RETURN_IF_FAILED(CopyFromVTL0ToVTL1(
        encryptedIsSecureIdOwnerId.get(),
        finishCreateRecallKey.encryptedIsSecureIdOwnerId,
        finishCreateRecallKey.encryptedIsSecureIdOwnerIdByteCount));

    finishCreateRecallKey.encryptedIsSecureIdOwnerId = encryptedIsSecureIdOwnerId.release();

    // Copy the encryptedCacheConfig from VTL0 to VTL1
    encryptedCacheConfig.reset(HeapAlloc(GetProcessHeap(), 0, finishCreateRecallKey.encryptedCacheConfigByteCount));
    RETURN_IF_NULL_ALLOC(encryptedCacheConfig);

    RETURN_IF_FAILED(CopyFromVTL0ToVTL1(
        encryptedCacheConfig.get(), finishCreateRecallKey.encryptedCacheConfig, finishCreateRecallKey.encryptedCacheConfigByteCount));

    finishCreateRecallKey.encryptedCacheConfig = encryptedCacheConfig.release();

    // Copy the encryptedPublicKey from VTL0 to VTL1
    encryptedPublicKey.reset(HeapAlloc(GetProcessHeap(), 0, finishCreateRecallKey.encryptedPublicKeyByteCount));
    RETURN_IF_NULL_ALLOC(encryptedPublicKey);

    RETURN_IF_FAILED(CopyFromVTL0ToVTL1(
        encryptedPublicKey.get(), finishCreateRecallKey.encryptedPublicKey, finishCreateRecallKey.encryptedPublicKeyByteCount));

    finishCreateRecallKey.encryptedPublicKey = encryptedPublicKey.release();
    cleanup.release();
    return S_OK;
}


HRESULT Verify_EnclaveSdk_LoadEncryptionKeySecuredByHello_Parameters(_In_ const veil::any::implementation::args::LoadEncryptionKeySecuredByHello* params, _Inout_ veil::any::implementation::args::LoadEncryptionKeySecuredByHello& finishLoadRecallKey)
{
    RETURN_HR_IF_NULL(E_INVALIDARG, params);
    RETURN_IF_FAILED(CopyFromVTL0ToVTL1(&finishLoadRecallKey, params));

    //RETURN_IF_FAILED(VerifySupportedKeyUsage(finishLoadRecallKey.keyUsage));

    // Validate the encryptedIsSecureIdOwnerId
    RETURN_HR_IF(E_INVALIDARG, finishLoadRecallKey.encryptedIsSecureIdOwnerIdByteCount == 0);
    RETURN_HR_IF_NULL(E_INVALIDARG, finishLoadRecallKey.encryptedIsSecureIdOwnerId);

    // Validate the encryptedHelloKeyEncryptionKey
    RETURN_HR_IF(E_INVALIDARG, finishLoadRecallKey.encryptedHelloKeyEncryptionKeyByteCount == 0);
    RETURN_HR_IF_NULL(E_INVALIDARG, finishLoadRecallKey.encryptedHelloKeyEncryptionKey);

    wil::unique_process_heap_ptr<void> sealedRecallKey;
    wil::unique_process_heap_ptr<void> encryptedIsSecureIdOwnerId;
    wil::unique_process_heap_ptr<void> encryptedHelloKeyEncryptionKey;

    auto cleanup = wil::scope_exit([&] {
        if (encryptedIsSecureIdOwnerId)
        {
            SecureZeroMemory(encryptedIsSecureIdOwnerId.get(), finishLoadRecallKey.encryptedIsSecureIdOwnerIdByteCount);
        }

        if (encryptedHelloKeyEncryptionKey)
        {
            SecureZeroMemory(encryptedHelloKeyEncryptionKey.get(), finishLoadRecallKey.encryptedHelloKeyEncryptionKeyByteCount);
        }

        if (sealedRecallKey)
        {
            SecureZeroMemory(sealedRecallKey.get(), finishLoadRecallKey.sealedRecallKeyByteCount);
        }
    });

    // Copy the encryptedIsSecureIdOwnerId from VTL0 to VTL1
    encryptedIsSecureIdOwnerId.reset(HeapAlloc(GetProcessHeap(), 0, finishLoadRecallKey.encryptedIsSecureIdOwnerIdByteCount));
    RETURN_IF_NULL_ALLOC(encryptedIsSecureIdOwnerId);

    RETURN_IF_FAILED(CopyFromVTL0ToVTL1(
        encryptedIsSecureIdOwnerId.get(), finishLoadRecallKey.encryptedIsSecureIdOwnerId, finishLoadRecallKey.encryptedIsSecureIdOwnerIdByteCount));

    finishLoadRecallKey.encryptedIsSecureIdOwnerId = encryptedIsSecureIdOwnerId.release();

    // Copy the encryptedHelloKeyEncryptionKey from VTL0 to VTL1
    encryptedHelloKeyEncryptionKey.reset(HeapAlloc(GetProcessHeap(), 0, finishLoadRecallKey.encryptedHelloKeyEncryptionKeyByteCount));
    RETURN_IF_NULL_ALLOC(encryptedHelloKeyEncryptionKey);

    RETURN_IF_FAILED(CopyFromVTL0ToVTL1(
        encryptedHelloKeyEncryptionKey.get(),
        finishLoadRecallKey.encryptedHelloKeyEncryptionKey,
        finishLoadRecallKey.encryptedHelloKeyEncryptionKeyByteCount));

    finishLoadRecallKey.encryptedHelloKeyEncryptionKey = encryptedHelloKeyEncryptionKey.release();

    // Validate the sealedRecallKey
    RETURN_HR_IF(E_INVALIDARG, finishLoadRecallKey.sealedRecallKeyByteCount == 0);
    RETURN_HR_IF_NULL(E_INVALIDARG, finishLoadRecallKey.sealedRecallKey);

    // Copy the sealedRecallKey from VTL0 to VTL1
    sealedRecallKey.reset(HeapAlloc(GetProcessHeap(), 0, finishLoadRecallKey.sealedRecallKeyByteCount));
    RETURN_IF_NULL_ALLOC(sealedRecallKey);
    RETURN_IF_FAILED(
        CopyFromVTL0ToVTL1(sealedRecallKey.get(), finishLoadRecallKey.sealedRecallKey, finishLoadRecallKey.sealedRecallKeyByteCount));

    finishLoadRecallKey.sealedRecallKey = sealedRecallKey.release();
    cleanup.release();

    return S_OK;
}
