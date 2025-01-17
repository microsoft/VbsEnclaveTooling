// © Microsoft Corporation. All rights reserved.

#include "pch.h"

#include <functional>
#include <map>
#include <vector>

#include <safeint.h>


#include <wil/stl.h>

//#include "shared_enclave.h"
#include "veil_arguments.any.h"

#include "crypto.vtl1.h"
#include "enclave_interface.vtl1.h"
#include "exports.vtl1.h"
#include "mutualauth.vtl1.h"
#include "paramvalidation.vtl1.h"
#include "registered_callbacks.vtl1.h"
#include "threadpool.vtl1.h"
#include "utils.vtl1.h"



#include "EnclaveServices.h"


// Indicate whether an enclave that runs with debugging turned on
// is permitted to unseal the data that a call to EnclaveSealData seals.
#ifdef _DEBUG
#define RECALL_ENCLAVE_RUNTIME_POLICY ENCLAVE_RUNTIME_POLICY_ALLOW_FULL_DEBUG
#else
#define RECALL_ENCLAVE_RUNTIME_POLICY 0
#endif

// Specify how another enclave must be related to the enclave
// that calls EnclaveSealData for the enclave to unseal the data.
#define RECALL_ENCLAVE_IDENTITY_POLICY ENCLAVE_IDENTITY_POLICY_SEAL_SAME_IMAGE

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


constexpr auto ENCLAVE_ENCRYPTED_RECALL_KEY_SIZE = SUPPORT_SHARED_SYMMETRIC_KEY_LENGTH_BYTES;
constexpr auto ENCLAVE_ENCRYPTED_RECALL_KEY_NONCE_SIZE = 12;
constexpr auto ENCLAVE_ENCRYPTED_RECALL_KEY_TAG_SIZE = 16;
constexpr auto ENCRYPTED_RECALL_KEY_INFO_VERSION = 1;

struct EncryptedRecallKeyInfo
{
    UINT32 version = ENCRYPTED_RECALL_KEY_INFO_VERSION;
    //RecallKeyUsage keyUsage;
    uint8_t nonce[ENCLAVE_ENCRYPTED_RECALL_KEY_NONCE_SIZE];
    uint8_t tag[ENCLAVE_ENCRYPTED_RECALL_KEY_TAG_SIZE];
    uint8_t key[ENCLAVE_ENCRYPTED_RECALL_KEY_SIZE];
};




/*
// RtlNtStatusToDosError converts STATUS_AUTH_TAG_MISMATCH to the very misleading
// HRESULT_FROM_WIN32(ERROR_CRC). Special-case that error and preserve it as itself.
inline HRESULT HResultFromBCryptStatus(NTSTATUS status)
{
    RETURN_HR_IF_EXPECTED((HRESULT)STATUS_AUTH_TAG_MISMATCH, status == STATUS_AUTH_TAG_MISMATCH);
    RETURN_IF_NTSTATUS_FAILED_EXPECTED(status);
    return S_OK;
}
*/


/*
HRESULT GetRandomNumber(_In_ ULONG randomByteCount, _Out_writes_bytes_(randomByteCount) PUCHAR random)
{
    return HRESULT_FROM_NT(BCryptGenRandom(SUPPORT_SHARED_RNG_ALG_HANDLE, random, randomByteCount, 0));
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
*/


//checks.h

/*
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
*/

/*
// utils.vtl1.h
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
*/







HRESULT DecryptData(BCRYPT_KEY_HANDLE symmetricKey, BYTE* buffer, ULONG bufferByteCount, std::vector<BYTE>& outDecryptedBytes)
{
    // Decrypt and verify the secure id is owner id state
    msl::utilities::SafeInt<UINT64> bufferStart(reinterpret_cast<ULONG_PTR>(buffer));
    msl::utilities::SafeInt<UINT64> bufferLength(bufferByteCount);
    msl::utilities::SafeInt<UINT64> bufferEnd = bufferStart + bufferLength;

    std::vector<BYTE> bufferBytes(static_cast<PUCHAR>(buffer), reinterpret_cast<PUCHAR>(bufferEnd.Ref()));

    std::vector<BYTE> decryptedBytes;
    RETURN_IF_FAILED(enclave_encryption::decrypt_data(symmetricKey, bufferBytes, decryptedBytes));
    RETURN_HR_IF(E_INVALIDARG, decryptedBytes.size() != sizeof(bool));

    outDecryptedBytes = std::move(decryptedBytes);

    return S_OK;
}

HRESULT MyDecryptAndVerifyIsSecureIdOwnerId(BCRYPT_KEY_HANDLE symmetricKey, BYTE* encryptedIsSecureIdOwnerId, ULONG encryptedIsSecureIdOwnerIdByteCount)
{
    std::vector<BYTE> decryptedIsSecureIdOwnerIdBytes;
    RETURN_IF_FAILED(DecryptData(symmetricKey, encryptedIsSecureIdOwnerId, encryptedIsSecureIdOwnerIdByteCount, decryptedIsSecureIdOwnerIdBytes));

    bool isSecureIdOwnerId = *reinterpret_cast<bool*>(decryptedIsSecureIdOwnerIdBytes.data());
    RETURN_HR_IF(E_INVALIDARG, !isSecureIdOwnerId);

    return S_OK;
}





//
//
//
namespace veil::vtl1
{
    namespace enclave_interface
    {
        // API
        namespace config
        {
            std::vector<std::wstring> g_allowedPackageFamilyNames;
            std::function<HRESULT(std::span<const veil::vtl1::enclave_interface::enclave_info>)> g_instancingEnforcementCallback;
            std::atomic<bool> g_isUnlocked;

            HRESULT set_allowed_package_family_names(std::span<PCWSTR> allowedPackageFamilyNames) noexcept
            try
            {
                g_allowedPackageFamilyNames = { allowedPackageFamilyNames.begin(), allowedPackageFamilyNames.end() };
                return S_OK;
            }
            CATCH_RETURN()

            HRESULT set_instancing_enforcement_callback(std::function<HRESULT(std::span<const veil::vtl1::enclave_interface::enclave_info>)>&& callback) noexcept
            try
            {
                g_instancingEnforcementCallback = std::move(callback);
                return S_OK;
            }
            CATCH_RETURN()
        }

        std::vector<uint8_t> owner_id()
        {
            ENCLAVE_INFORMATION info;
            //THROW_IF_FAILED(enclaveServices.GetEnclaveInformation(sizeof(ENCLAVE_INFORMATION), &info));
            THROW_IF_FAILED(::EnclaveGetEnclaveInformation(sizeof(ENCLAVE_INFORMATION), &info));

            //auto ownerId = std::vector<uint8_t>(IMAGE_ENCLAVE_LONG_ID_LENGTH);
            //auto ownerId = std::vector<uint8_t>(sizeof(ENCLAVE_IDENTITY::OwnerId));
            auto ownerId = std::vector<uint8_t>(sizeof(info.Identity.OwnerId));

            // Fill in the GUID components - first 8 bytes of the feature name, 8 bytes of the ownerId
            //std::memcpy(ownerId.data(), &info.Identity.OwnerId, IMAGE_ENCLAVE_LONG_ID_LENGTH);
            std::memcpy(ownerId.data(), &info.Identity.OwnerId, sizeof(info.Identity.OwnerId));
            return ownerId;
        }

        bool is_unlocked()
        {
            return config::g_isUnlocked;
        }
    }
}





//wil::unique_bcrypt_key m_symmetricKey;
    //std::map<UINT64, symmetric_key> sessions;
static constexpr size_t c_symmetricKeySize = 32;
using symmetric_key = std::array<BYTE, c_symmetricKeySize>;

namespace eif_objects_table
{
    std::map<UINT64, wil::unique_bcrypt_key> keys;
    std::map<size_t, std::pair<size_t, std::vector<uint8_t>>> challenges;

    inline UINT64 make_handle()
    {
        static UINT64 i = 0;
        return i++;
    }

    //
    // Keys
    //
    inline UINT64 add_key(wil::unique_bcrypt_key&& key)
    {
        auto handle = make_handle();
        keys[handle] = std::move(key);
        return handle;
    }

    inline BCRYPT_KEY_HANDLE get_key(UINT64 handle)
    {
        return keys[handle].get();
    }

    //
    // Sessions
    //
    inline UINT64 add_session(wil::unique_bcrypt_key&& sessionKey)
    {
        return add_key(std::move(sessionKey));
    }

    inline BCRYPT_KEY_HANDLE get_session(UINT64 handle)
    {
        return get_key(handle);
    }

    //
    // Challenges
    //
    inline void add_challenge(size_t purpose, size_t count, std::vector<uint8_t>&& challenge)
    {
        //todo:jw lock
        bool exists = challenges.find(purpose) != challenges.end();
        if (exists)
        {
            THROW_HR(CERTSRV_E_EXPIRED_CHALLENGE);
        }
        challenges.emplace(purpose, std::make_pair(count, std::move(challenge)));
    }

    inline std::vector<uint8_t> consume_challenge(size_t purpose)
    {
        // Take a lock
        auto it = challenges.find(purpose);
        if (it == challenges.end())
        {
            THROW_HR(TPM_E_ATTESTATION_CHALLENGE_NOT_SET);
        }
        else if (it->second.first <= 0)
        {
            THROW_HR(CERTSRV_E_EXPIRED_CHALLENGE);
        }
        it->second.first--;
        return std::move(it->second.second);
    }
};

namespace enclave_handles
{
    using namespace eif_objects_table;
};


namespace veil::vtl1::implementation::exports
{
    HRESULT StartHelloSession(_Inout_ veil::any::implementation::args::StartHelloSession* vtl0params)
        try
    {

        veil::any::implementation::args::StartHelloSession startCreateOrLoadRecallKey = {};

        RETURN_IF_FAILED(VerifyStartHelloSessionParameters(vtl0params, startCreateOrLoadRecallKey));

        auto cleanup = wil::scope_exit([&]
        {
            if (startCreateOrLoadRecallKey.challenge != nullptr)
            {
                RtlSecureZeroMemory(startCreateOrLoadRecallKey.challenge, startCreateOrLoadRecallKey.challengeByteCount);
                HeapFree(GetProcessHeap(), 0, startCreateOrLoadRecallKey.challenge);
            }
        });

        // Params are valid (and now local to VTL1), do the work

        // We need to return a blob, sealed for the NGC trustlet, containing the enclave's attestation report, the challenge provided
        // by NGC and a newly minted symmetric key

        // SafeInt pointer arithmetic
        msl::utilities::SafeInt<UINT64> challengeStart(reinterpret_cast<ULONG_PTR>(startCreateOrLoadRecallKey.challenge));
        msl::utilities::SafeInt<UINT64> challengeLength(startCreateOrLoadRecallKey.challengeByteCount);
        msl::utilities::SafeInt<UINT64> challengeEnd = challengeStart + challengeLength;

        std::vector<BYTE> enclaveData(ENCLAVE_REPORT_DATA_LENGTH);
        std::vector<BYTE> challenge(
            startCreateOrLoadRecallKey.challenge, reinterpret_cast<PBYTE>(static_cast<ULONG_PTR>(challengeEnd.Ref())));

        veil::vtl1::utils::symmetric_secret symmetricSecret;
        RETURN_IF_FAILED(veil::vtl1::utils::GenerateSymmetricSecret(symmetricSecret));

        RETURN_IF_FAILED(veil::vtl1::utils::GetAttestationForSessionChallenge(symmetricSecret, challenge, enclaveData));

        wil::unique_bcrypt_key symmetricSessionKey;
        RETURN_IF_FAILED(veil::vtl1::utils::GenerateSymmetricKey(symmetricSecret, symmetricSessionKey));

        //todo:jw make raii
        auto sessionHandle = enclave_handles::add_session(std::move(symmetricSessionKey));

        ////////
        ////////////RETURN_IF_FAILED(recallKeyState.GetAuthSession().GetAttestationForSessionChallenge(enclaveServices, challenge, enclaveData));
        ////////

        // For now, return the attestation data directly, because that's what NGC currently expects. This may change when we have the
        // encryption API from SK, or GetAttestationForSessionChallenge might be updated to call that encryption API.
        {
            UINT32 encryptedAttestationReportSize = static_cast<UINT32>(enclaveData.size());
            if (startCreateOrLoadRecallKey.sealedAttestationBlobByteCount < encryptedAttestationReportSize)
            {
                RETURN_IF_FAILED(CopyFromVTL1ToVTL0(
                    &vtl0params->sealedAttestationBlobByteCount, &encryptedAttestationReportSize, sizeof(encryptedAttestationReportSize)));
                //activity.Stop(HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER));
                return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
            }

            RETURN_IF_FAILED(CopyFromVTL1ToVTL0(
                &vtl0params->sealedAttestationBlobByteCount, &encryptedAttestationReportSize, sizeof(encryptedAttestationReportSize)));
            RETURN_IF_FAILED(
                CopyFromVTL1ToVTL0(startCreateOrLoadRecallKey.sealedAttestationBlob, enclaveData.data(), encryptedAttestationReportSize));

            vtl0params->sessionHandle = sessionHandle;
        }

        //activity.Stop();
        return S_OK;
    }
    CATCH_RETURN()

        HRESULT CreateAttestationReport(_Inout_ veil::any::implementation::args::CreateAttestationReport* vtl0params)
        try
    {
        auto span = std::span(vtl0params->enclaveReportData, vtl0params->enclaveReportDataByteCount);

        auto enclaveReportData = std::vector<uint8_t>(ENCLAVE_REPORT_DATA_LENGTH);
        std::copy(span.begin(), span.end(), enclaveReportData.begin());

        auto report = std::vector<uint8_t>();
        RETURN_IF_FAILED(veil::vtl1::utils::GetAttestationReport(enclaveReportData, report));

        vtl0params->attestationReportByteCount = (UINT32)report.size() - 10;
        memcpy(vtl0params->attestationReport, report.data(), report.size());
        return S_OK;
    }
    CATCH_RETURN()


        HRESULT GenerateEncryptionKeySecuredByHello(_Inout_ veil::any::implementation::args::GenerateEncryptionKeySecuredByHello* params)
        try
    {

        veil::any::implementation::args::GenerateEncryptionKeySecuredByHello finishCreateRecallKey = {};

        RETURN_IF_FAILED(VerifyGenerateEncryptionKeySecuredByHelloParameters(params, finishCreateRecallKey));

        ULONG kekSize = 0;
        wil::unique_process_heap_ptr<UCHAR> kekBytes;
        ULONG ecdhPublicKeySize = 0;
        wil::unique_process_heap_ptr<UCHAR> ecdhPublicKey;

        auto cleanup = wil::scope_exit([&]
        {
            if (kekBytes)
            {
                RtlSecureZeroMemory(kekBytes.get(), kekSize);
            }

            if (ecdhPublicKey)
            {
                RtlSecureZeroMemory(ecdhPublicKey.get(), ecdhPublicKeySize);
            }

            if (finishCreateRecallKey.encryptedIsSecureIdOwnerId != nullptr)
            {
                RtlSecureZeroMemory(finishCreateRecallKey.encryptedIsSecureIdOwnerId, finishCreateRecallKey.encryptedIsSecureIdOwnerIdByteCount);
                HeapFree(GetProcessHeap(), 0, finishCreateRecallKey.encryptedIsSecureIdOwnerId);
            }

            if (finishCreateRecallKey.encryptedCacheConfig != nullptr)
            {
                RtlSecureZeroMemory(finishCreateRecallKey.encryptedCacheConfig, finishCreateRecallKey.encryptedCacheConfigByteCount);
                HeapFree(GetProcessHeap(), 0, finishCreateRecallKey.encryptedCacheConfig);
            }

            if (finishCreateRecallKey.encryptedPublicKey != nullptr)
            {
                RtlSecureZeroMemory(finishCreateRecallKey.encryptedPublicKey, finishCreateRecallKey.encryptedPublicKeyByteCount);
                HeapFree(GetProcessHeap(), 0, finishCreateRecallKey.encryptedPublicKey);
            }
        });

        // Params are valid (and now local to VTL1), do the work
        //wil::cs_leave_scope_exit lock;
        //RecallKeyState& recallKeyState = RecallKeyState::Get(finishCreateRecallKey.keyUsage, lock);

        // recallKeyState should be authenticated, but not loaded at this point (should contain the symmetric key generated during
        // StartCreateOrLoadRecallKey).
        //RETURN_HR_IF_FALSE(E_UNEXPECTED, recallKeyState.authenticated());
        //RETURN_HR_IF(E_UNEXPECTED, recallKeyState.loaded());

        auto sessionKeyHandle = enclave_handles::get_session(finishCreateRecallKey.sessionHandle);

        // NGC<->Enclave message
        // Decrypt and verify the owner id state
        RETURN_IF_FAILED(MyDecryptAndVerifyIsSecureIdOwnerId(
            sessionKeyHandle,
            static_cast<PBYTE>(finishCreateRecallKey.encryptedIsSecureIdOwnerId),
            finishCreateRecallKey.encryptedIsSecureIdOwnerIdByteCount));

        // NGC<->Enclave message
        // Decrypt and verify the cache config
        /*
        RETURN_IF_FAILED(MyDecryptAndVerifyNGCCacheConfig(
            sessionKey.get(),
            finishCreateRecallKey.keyUsage,
            static_cast<PBYTE>(finishCreateRecallKey.encryptedCacheConfig),
            finishCreateRecallKey.encryptedCacheConfigByteCount));
        */

        // NGC<->Enclave message
        // Decrypt the public key
        std::vector<BYTE> decryptedPublicKeyBytes;

        msl::utilities::SafeInt<UINT64> encryptedPublicKeyStart(reinterpret_cast<ULONG_PTR>(finishCreateRecallKey.encryptedPublicKey));
        msl::utilities::SafeInt<UINT64> encryptedPublicKeyLength(finishCreateRecallKey.encryptedPublicKeyByteCount);
        msl::utilities::SafeInt<UINT64> encryptedPublicKeyEnd = encryptedPublicKeyStart + encryptedPublicKeyLength;
        std::vector<BYTE> encryptedPublicKeyBytes(
            static_cast<PUCHAR>(finishCreateRecallKey.encryptedPublicKey), reinterpret_cast<PUCHAR>(encryptedPublicKeyEnd.Ref()));

        //RETURN_IF_FAILED(recallKeyState.GetAuthSession().DecryptData(encryptedPublicKeyBytes, decryptedPublicKeyBytes));
        RETURN_IF_FAILED(enclave_encryption::decrypt_data(sessionKeyHandle, encryptedPublicKeyBytes, decryptedPublicKeyBytes));


        // Import the public key
        wil::unique_bcrypt_key publicKey;
        RETURN_IF_NTSTATUS_FAILED(BCryptImportKeyPair(
            SUPPORT_SHARED_PUBLIC_KEY_ALG_HANDLE,
            nullptr,
            SUPPORT_SHARED_PUBLIC_KEY_BLOB_TYPE,
            &publicKey,
            decryptedPublicKeyBytes.data(),
            static_cast<ULONG>(decryptedPublicKeyBytes.size()),
            0));

        // Create ephemeral DH key
        wil::unique_bcrypt_key ecdhKeyPair;
        RETURN_IF_NTSTATUS_FAILED(BCryptGenerateKeyPair(SUPPORT_SHARED_DH_KEY_ALG_HANDLE, &ecdhKeyPair, SUPPORT_SHARED_DH_KEY_LENGTH_BITS, 0));
        RETURN_IF_NTSTATUS_FAILED(BCryptFinalizeKeyPair(ecdhKeyPair.get(), 0));

        // Perform ECDH key exchange
        wil::unique_bcrypt_secret ecdhSecret;
        RETURN_IF_NTSTATUS_FAILED(BCryptSecretAgreement(ecdhKeyPair.get(), publicKey.get(), &ecdhSecret, 0));

        // Derive a key to use as a Key-Encryption-Key (KEK)
        RETURN_IF_NTSTATUS_FAILED(BCryptDeriveKey(ecdhSecret.get(), BCRYPT_KDF_RAW_SECRET, nullptr, nullptr, 0, &kekSize, 0));

        kekBytes.reset(static_cast<PUCHAR>(HeapAlloc(GetProcessHeap(), 0, kekSize)));
        RETURN_IF_NULL_ALLOC(kekBytes);

        RETURN_IF_NTSTATUS_FAILED(BCryptDeriveKey(ecdhSecret.get(), BCRYPT_KDF_RAW_SECRET, nullptr, kekBytes.get(), kekSize, &kekSize, 0));

        wil::unique_bcrypt_key kek;
        RETURN_IF_NTSTATUS_FAILED(
            BCryptGenerateSymmetricKey(SUPPORT_SHARED_SYMMETRIC_KEY_ALG_HANDLE, &kek, nullptr, 0, kekBytes.get(), kekSize, 0));

        // Export the public key
        RETURN_IF_NTSTATUS_FAILED(BCryptExportKey(ecdhKeyPair.get(), nullptr, BCRYPT_ECCPUBLIC_BLOB, nullptr, 0, &ecdhPublicKeySize, 0));

        // Check whether caller allocated a large enough buffer
        if (finishCreateRecallKey.ecdhPublicKeyByteCount < ecdhPublicKeySize)
        {
            RETURN_IF_FAILED(CopyFromVTL1ToVTL0(&params->ecdhPublicKeyByteCount, &ecdhPublicKeySize, sizeof(ecdhPublicKeySize)));
            //activity.Stop(HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER));
            return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
        }

        ecdhPublicKey.reset(static_cast<PUCHAR>(HeapAlloc(GetProcessHeap(), 0, ecdhPublicKeySize)));
        RETURN_IF_NULL_ALLOC(ecdhPublicKey);

        RETURN_IF_NTSTATUS_FAILED(BCryptExportKey(
            ecdhKeyPair.get(), nullptr, BCRYPT_ECCPUBLIC_BLOB, ecdhPublicKey.get(), ecdhPublicKeySize, &ecdhPublicKeySize, 0));

        // Generate the Recall key and return it encrypted with the KEK and sealed.
        wil::secure_vector<uint8_t> recallKeyBytes(SUPPORT_SHARED_SYMMETRIC_KEY_LENGTH_BYTES);
        RETURN_IF_FAILED(veil::vtl1::cypto::GetRandomNumber(SUPPORT_SHARED_SYMMETRIC_KEY_LENGTH_BYTES, recallKeyBytes.data()));

        wil::unique_bcrypt_key recallKey;
        RETURN_IF_NTSTATUS_FAILED(BCryptGenerateSymmetricKey(
            SUPPORT_SHARED_SYMMETRIC_KEY_ALG_HANDLE, &recallKey, nullptr, 0, recallKeyBytes.data(), static_cast<ULONG>(recallKeyBytes.size()), 0));
        //RecallKeyState::LoadKeyForUsage(finishCreateRecallKey.keyUsage, recallKey, recallKeyBytes);

        // Encrypt the Recall key with the KEK
        EncryptedRecallKeyInfo encryptedRecallKeyInfo = {};
        encryptedRecallKeyInfo.version = ENCRYPTED_RECALL_KEY_INFO_VERSION;
        //encryptedRecallKeyInfo.keyUsage = finishCreateRecallKey.keyUsage;

        RETURN_IF_FAILED(veil::vtl1::cypto::GetRandomNumber(ARRAYSIZE(encryptedRecallKeyInfo.nonce), encryptedRecallKeyInfo.nonce));

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO cipherInfo{};
        BCRYPT_INIT_AUTH_MODE_INFO(cipherInfo);
        cipherInfo.pbNonce = encryptedRecallKeyInfo.nonce;
        cipherInfo.cbNonce = ARRAYSIZE(encryptedRecallKeyInfo.nonce);
        cipherInfo.pbTag = encryptedRecallKeyInfo.tag;
        cipherInfo.cbTag = ARRAYSIZE(encryptedRecallKeyInfo.tag);

        ULONG encryptedRecallKeySize = ARRAYSIZE(encryptedRecallKeyInfo.key);
        // The Recall Key bytes are not loaded into the key state, so
        // grab them from there
        //recallKeyBytes = recallKeyState.GetRecallKeyMaterial();
        RETURN_IF_NTSTATUS_FAILED(BCryptEncrypt(
            kek.get(),
            recallKeyBytes.data(),
            static_cast<ULONG>(recallKeyBytes.size()),
            &cipherInfo,
            nullptr,
            0,
            encryptedRecallKeyInfo.key,
            encryptedRecallKeySize,
            &encryptedRecallKeySize,
            0));

        // Seal the encrypted Recall key
        UINT32 sealedRecallKeyInfoSize = 0;
        IEnclaveServices& enclaveServices = GetEnclaveServices();
        RETURN_IF_FAILED(enclaveServices.SealData(
            &encryptedRecallKeyInfo, sizeof(encryptedRecallKeyInfo), RECALL_ENCLAVE_IDENTITY_POLICY, RECALL_ENCLAVE_RUNTIME_POLICY, nullptr, 0, &sealedRecallKeyInfoSize));

        // Return the sealed Recall key to the caller
        if (finishCreateRecallKey.sealedEncryptedRecallKeyByteCount < sealedRecallKeyInfoSize)
        {
            RETURN_IF_FAILED(CopyFromVTL1ToVTL0(
                &params->sealedEncryptedRecallKeyByteCount, &sealedRecallKeyInfoSize, sizeof(sealedRecallKeyInfoSize)));
            //activity.Stop(HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER));
            return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
        }

        wil::unique_process_heap_ptr<UCHAR> sealedRecallKeyInfo{ static_cast<PUCHAR>(HeapAlloc(GetProcessHeap(), 0, sealedRecallKeyInfoSize)) };
        RETURN_IF_NULL_ALLOC(sealedRecallKeyInfo);

        RETURN_IF_FAILED(enclaveServices.SealData(
            &encryptedRecallKeyInfo,
            sizeof(encryptedRecallKeyInfo),
            RECALL_ENCLAVE_IDENTITY_POLICY,
            RECALL_ENCLAVE_RUNTIME_POLICY,
            sealedRecallKeyInfo.get(),
            sealedRecallKeyInfoSize,
            &sealedRecallKeyInfoSize));

        RETURN_IF_FAILED(
            CopyFromVTL1ToVTL0(&params->sealedEncryptedRecallKeyByteCount, &sealedRecallKeyInfoSize, sizeof(sealedRecallKeyInfoSize)));
        RETURN_IF_FAILED(CopyFromVTL1ToVTL0(params->sealedEncryptedRecallKey, sealedRecallKeyInfo.get(), sealedRecallKeyInfoSize));

        // Return the ephemeral public key to the caller to store.
        RETURN_IF_FAILED(CopyFromVTL1ToVTL0(&params->ecdhPublicKeyByteCount, &ecdhPublicKeySize, sizeof(ecdhPublicKeySize)));
        RETURN_IF_FAILED(CopyFromVTL1ToVTL0(params->ecdhPublicKey, ecdhPublicKey.get(), ecdhPublicKeySize));

        //activity.Stop();
        return S_OK;
    }
    CATCH_RETURN()



    HRESULT LoadEncryptionKeySecuredByHello(_Inout_ veil::any::implementation::args::LoadEncryptionKeySecuredByHello* params)
        try
    {
        veil::any::implementation::args::LoadEncryptionKeySecuredByHello finishLoadRecallKey = {};

        RETURN_IF_FAILED(Verify_EnclaveSdk_LoadEncryptionKeySecuredByHello_Parameters(params, finishLoadRecallKey));

        UINT32 encryptedRecallKeyInfoSize = sizeof(EncryptedRecallKeyInfo);
        wil::unique_process_heap_ptr<EncryptedRecallKeyInfo> unsealedRecallKey;

        auto cleanup = wil::scope_exit([&]
        {
            if (unsealedRecallKey)
            {
                RtlSecureZeroMemory(unsealedRecallKey.get(), encryptedRecallKeyInfoSize);
            }

            if (finishLoadRecallKey.encryptedIsSecureIdOwnerId != nullptr)
            {
                RtlSecureZeroMemory(finishLoadRecallKey.encryptedIsSecureIdOwnerId, finishLoadRecallKey.encryptedIsSecureIdOwnerIdByteCount);
                HeapFree(GetProcessHeap(), 0, finishLoadRecallKey.encryptedIsSecureIdOwnerId);
            }

            if (finishLoadRecallKey.encryptedHelloKeyEncryptionKey != nullptr)
            {
                RtlSecureZeroMemory(
                    finishLoadRecallKey.encryptedHelloKeyEncryptionKey, finishLoadRecallKey.encryptedHelloKeyEncryptionKeyByteCount);
                HeapFree(GetProcessHeap(), 0, finishLoadRecallKey.encryptedHelloKeyEncryptionKey);
            }

            if (finishLoadRecallKey.sealedRecallKey != nullptr)
            {
                RtlSecureZeroMemory(finishLoadRecallKey.sealedRecallKey, finishLoadRecallKey.sealedRecallKeyByteCount);
                HeapFree(GetProcessHeap(), 0, finishLoadRecallKey.sealedRecallKey);
            }
        });

        // Params are valid (and now local to VTL1), do the work
        wil::cs_leave_scope_exit lock;
        //RecallKeyState& recallKeyState = RecallKeyState::Get(finishLoadRecallKey.keyUsage, lock);

        // recallKeyState should be authenticated at this point (should contain the symmetric key generated during StartCreateOrLoadRecallKey)
        //RETURN_HR_IF_FALSE(E_UNEXPECTED, recallKeyState.authenticated());
        //RETURN_HR_IF(E_UNEXPECTED, recallKeyState.loaded());

        // NGC<->Enclave message
        // Decrypt and verify the owner id state
        /*
        RETURN_IF_FAILED(DecryptAndVerifyIsSecureIdOwnerId(
            recallKeyState,
            static_cast<PBYTE>(finishLoadRecallKey.encryptedIsSecureIdOwnerId),
            finishLoadRecallKey.encryptedIsSecureIdOwnerIdByteCount));
        */

        auto sessionKeyHandle = enclave_handles::get_session(finishLoadRecallKey.sessionHandle);

        RETURN_IF_FAILED(MyDecryptAndVerifyIsSecureIdOwnerId(
            sessionKeyHandle,
            static_cast<PBYTE>(finishLoadRecallKey.encryptedIsSecureIdOwnerId),
            finishLoadRecallKey.encryptedIsSecureIdOwnerIdByteCount));


        // NGC<->Enclave message
        // Decrypt the Hello Key-Encryption-Key (KEK)
        msl::utilities::SafeInt<UINT64> encryptedHelloKEKStart(reinterpret_cast<ULONG_PTR>(finishLoadRecallKey.encryptedHelloKeyEncryptionKey));
        msl::utilities::SafeInt<UINT64> encryptedHelloKEKLength(finishLoadRecallKey.encryptedHelloKeyEncryptionKeyByteCount);
        msl::utilities::SafeInt<UINT64> encryptedHelloKEKEnd = encryptedHelloKEKStart + encryptedHelloKEKLength;

        std::vector<BYTE> encryptedHelloKEK(
            static_cast<PUCHAR>(finishLoadRecallKey.encryptedHelloKeyEncryptionKey),
            reinterpret_cast<PUCHAR>(static_cast<ULONG_PTR>(encryptedHelloKEKEnd.Ref())));
        std::vector<BYTE> decryptedHelloKEK;

        //RETURN_IF_FAILED(recallKeyState.GetAuthSession().DecryptData(encryptedHelloKEK, decryptedHelloKEK));
        RETURN_IF_FAILED(enclave_encryption::decrypt_data(sessionKeyHandle, encryptedHelloKEK, decryptedHelloKEK));

        // Load the Hello KEK
        wil::unique_bcrypt_key helloKEK;
        RETURN_IF_NTSTATUS_FAILED(BCryptGenerateSymmetricKey(
            SUPPORT_SHARED_SYMMETRIC_KEY_ALG_HANDLE,
            &helloKEK,
            nullptr,
            0,
            decryptedHelloKEK.data(),
            static_cast<ULONG>(decryptedHelloKEK.size()),
            0));

        // Unseal the recall key
        unsealedRecallKey.reset(static_cast<EncryptedRecallKeyInfo*>(HeapAlloc(GetProcessHeap(), 0, sizeof(EncryptedRecallKeyInfo))));
        IEnclaveServices& enclaveServices = GetEnclaveServices();
        RETURN_IF_FAILED(enclaveServices.UnsealData(
            finishLoadRecallKey.sealedRecallKey,
            (UINT32)finishLoadRecallKey.sealedRecallKeyByteCount,
            unsealedRecallKey.get(),
            encryptedRecallKeyInfoSize,
            &encryptedRecallKeyInfoSize,
            nullptr,
            nullptr));

        RETURN_HR_IF(E_UNEXPECTED, unsealedRecallKey->version != ENCRYPTED_RECALL_KEY_INFO_VERSION);
        //RETURN_HR_IF(E_UNEXPECTED, unsealedRecallKey->keyUsage != finishLoadRecallKey.keyUsage);

        // Decrypt the Recall key
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO cipherInfo{};
        BCRYPT_INIT_AUTH_MODE_INFO(cipherInfo);
        cipherInfo.pbNonce = unsealedRecallKey->nonce;
        cipherInfo.cbNonce = ARRAYSIZE(unsealedRecallKey->nonce);
        cipherInfo.pbTag = unsealedRecallKey->tag;
        cipherInfo.cbTag = ARRAYSIZE(unsealedRecallKey->tag);

        ULONG decryptedRecallKeyBytesCount = ARRAYSIZE(unsealedRecallKey->key);
        wil::secure_vector<uint8_t> decryptedRecallKeyBytes(decryptedRecallKeyBytesCount);
        RETURN_IF_FAILED(HResultFromBCryptStatus(BCryptDecrypt(
            helloKEK.get(),
            unsealedRecallKey->key,
            ARRAYSIZE(unsealedRecallKey->key),
            &cipherInfo,
            nullptr,
            0,
            decryptedRecallKeyBytes.data(),
            decryptedRecallKeyBytesCount,
            &decryptedRecallKeyBytesCount,
            0)));

        // Load the Recall Key
        wil::unique_bcrypt_key recallKey;
        RETURN_IF_NTSTATUS_FAILED(BCryptGenerateSymmetricKey(
            SUPPORT_SHARED_SYMMETRIC_KEY_ALG_HANDLE, &recallKey, nullptr, 0, decryptedRecallKeyBytes.data(), decryptedRecallKeyBytesCount, 0));
        //RecallKeyState::LoadKeyForUsage(finishLoadRecallKey.keyUsage, recallKey, decryptedRecallKeyBytes);
        auto keyHandle = enclave_handles::add_key(std::move(recallKey));

        params->encryptionKeyHandle = keyHandle;

        //activity.Stop();
        return S_OK;
    }
    CATCH_RETURN()

        HRESULT ExportKey(_Inout_ veil::any::implementation::args::ExportKey* params)
        try
    {
        // todo:jw return error if not debug mode and key doesn't have debug flag set
        auto key = enclave_handles::get_key(params->encryptionKeyHandle);

        DWORD blobSize = 0;

        // Get the size of the key blob
        RETURN_IF_NTSTATUS_FAILED(BCryptExportKey(key, nullptr, BCRYPT_KEY_DATA_BLOB, nullptr, 0, &blobSize, 0));

        // Allocate buffer for the key blob
        std::vector<BYTE> blob(blobSize);

        // Export the key
        RETURN_IF_NTSTATUS_FAILED(BCryptExportKey(key, nullptr, BCRYPT_KEY_DATA_BLOB, blob.data(), blobSize, &blobSize, 0));
        blob.resize(blobSize);

        params->keyDataByteCount = blobSize;
        memcpy(params->keyData, blob.data(), blobSize);

        return S_OK;
    }
    CATCH_RETURN()

#define CHALLENGE_PURPOSE__ENCLAVE_IDENTITY_ATTESTATION 0x0000000012345678

        HRESULT GetPackagedEnclaveIdentityProofChallenge(_Inout_ veil::any::implementation::args::GetPackagedEnclaveIdentityProofChallenge* params)
        try
    {
        std::vector<uint8_t> challenge(32);
        RETURN_IF_FAILED(HRESULT_FROM_NT(BCryptGenRandom(nullptr, challenge.data(), static_cast<ULONG>(challenge.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG)));

        params->challengeByteCount = (UINT32)challenge.size();
        memcpy(params->challenge, challenge.data(), challenge.size());

        enclave_handles::add_challenge(CHALLENGE_PURPOSE__ENCLAVE_IDENTITY_ATTESTATION, 1, std::move(challenge));

        return S_OK;
    }
    CATCH_RETURN()

        HRESULT x(void* Context, void* OwnerId, void* Challenge)
    {
        // from %SDXROOT%\minkernel\ium\tests\vencl\enclave\attest.cpp
        PUCHAR Report = NULL;
        DWORD ReportSize;
        VBS_ENCLAVE_REPORT_PKG_HEADER* PkgHeader;
        VBS_ENCLAVE_REPORT* EnclaveReport;
        VBS_ENCLAVE_REPORT_MODULE* Module;
        ULONG EnclaveType;
        UCHAR ZeroID[IMAGE_ENCLAVE_LONG_ID_LENGTH] = { 0 };
        BOOL SystemModulePresent = FALSE;
        DWORD PkgSizeRemaining;
        DWORD ReportSizeRemaining;
        SIZE_T FileNameLengthBytes;
        SIZE_T FileNameLengthChars;

        Report = (PUCHAR)Context;
        PkgHeader = (VBS_ENCLAVE_REPORT_PKG_HEADER*)Report;
        ReportSize = PkgHeader->PackageSize;

        //
        // Read the enclave type from the enclave report prior to validation.  If
        // the report is large enough, assume the report type is at least good
        // enough to perform report validation.
        //

        if (ReportSize < sizeof(VBS_ENCLAVE_REPORT_PKG_HEADER) + sizeof(VBS_ENCLAVE_REPORT))
        {
            RETURN_HR(E_FAIL);
        }

        EnclaveReport = (VBS_ENCLAVE_REPORT*)(Report + sizeof(VBS_ENCLAVE_REPORT_PKG_HEADER));

        EnclaveType = EnclaveReport->EnclaveIdentity.EnclaveType;
        if (EnclaveType != ENCLAVE_TYPE_VBS)
        {

            RETURN_HR(E_FAIL);
        }

        //
        // Verify the report signature.
        //

        RETURN_IF_FAILED(EnclaveVerifyAttestationReport(EnclaveType,
            Report,
            ReportSize));

        //
        // Verify various report fields.
        //

        PkgSizeRemaining = ReportSize;

        PkgHeader = (VBS_ENCLAVE_REPORT_PKG_HEADER*)Report;

        if ((PkgHeader->Version != VBS_ENCLAVE_REPORT_PKG_HEADER_VERSION_CURRENT) ||
            (PkgHeader->SignatureScheme != VBS_ENCLAVE_REPORT_SIGNATURE_SCHEME_SHA256_RSA_PSS_SHA256) ||
            (PkgHeader->SignedStatementSize < sizeof(VBS_ENCLAVE_REPORT)) ||
            (PkgHeader->SignatureSize < 256) ||
            (PkgHeader->Reserved != 0))
        {

            RETURN_HR(E_FAIL);
        }

        PkgSizeRemaining -= sizeof(VBS_ENCLAVE_REPORT_PKG_HEADER);

        if ((EnclaveReport->ReportSize < sizeof(VBS_ENCLAVE_REPORT)))
        {
            RETURN_HR(E_FAIL);
        }

        if ((EnclaveReport->ReportVersion != VBS_ENCLAVE_REPORT_VERSION_CURRENT))
        {
            RETURN_HR(E_FAIL);
        }

        if (EnclaveReport->EnclaveIdentity.EnclaveSvn != 0)
        {
            //RETURN_HR(E_FAIL);
        }

        if (EnclaveReport->EnclaveIdentity.SigningLevel != 0)
        {
            RETURN_HR(E_FAIL);
        }

        if (memcmp(EnclaveReport->EnclaveData, OwnerId, ENCLAVE_REPORT_DATA_LENGTH - 32) != 0)
        {
            RETURN_HR(E_FAIL);
        }

        if (memcmp(EnclaveReport->EnclaveData + 32, Challenge, ENCLAVE_REPORT_DATA_LENGTH - 32) != 0)
        {
            RETURN_HR(E_FAIL);
        }

        ReportSizeRemaining = EnclaveReport->ReportSize;

#if 0
        //
        // Make sure the UniqueId is not all zeros.
        //

        if (memcmp(EnclaveReport->UniqueId, ZeroID, sizeof(ZeroID)) == 0)
        {
            return NULL;
        }
#endif

        Module = (VBS_ENCLAVE_REPORT_MODULE*)(Report + sizeof(VBS_ENCLAVE_REPORT_PKG_HEADER) + sizeof(VBS_ENCLAVE_REPORT));

        PkgSizeRemaining -= sizeof(VBS_ENCLAVE_REPORT);
        ReportSizeRemaining -= sizeof(VBS_ENCLAVE_REPORT);

        //
        // A basic enclave should report no modules, while a full enclave should
        // report at least the platform module.
        //

        if (ReportSizeRemaining == 0)
        {
            RETURN_HR(E_FAIL);
        }

        bool foundValidAppInfoEnclave = false;

        while (ReportSizeRemaining > 0)
        {

            if ((ReportSizeRemaining < sizeof(VBS_ENCLAVE_REPORT_MODULE)) ||
                (Module->Header.DataType != VBS_ENCLAVE_VARDATA_MODULE) ||
                (Module->Header.Size < sizeof(VBS_ENCLAVE_REPORT_MODULE)))
            {

                RETURN_HR(E_FAIL);
            }

            FileNameLengthBytes = Module->Header.Size - FIELD_OFFSET(VBS_ENCLAVE_REPORT_MODULE, ModuleName);

            //
            // Require a file name of at least one wchar long plus zero termination.
            //

            if ((FileNameLengthBytes < 2 * sizeof(WCHAR)) ||
                ((FileNameLengthBytes % sizeof(WCHAR)) != 0))
            {
                RETURN_HR(E_FAIL);
            }

            FileNameLengthChars = FileNameLengthBytes / sizeof(WCHAR);

            //
            // Verify the file name is zero-terminated.
            //

            if (Module->ModuleName[FileNameLengthChars - 1] != 0)
            {
                RETURN_HR(E_FAIL);
            }

            //
            // Check for the system module name.
            //

            if (wcscmp(Module->ModuleName, L"vertdll.dll") == 0)
            {

                SystemModulePresent = TRUE;

                //
                // Make sure the UniqueId is not all zeros.
                //

                if (memcmp(Module->UniqueId, ZeroID, sizeof(ZeroID)) == 0)
                {
                    RETURN_HR(E_FAIL);
                }
            }

            // appinfo enclave check //todo:jw
#define APPINFOSVC_ENCLAVE_IMAGE_NAME L"sample_enclave.dll"
            if (wcscmp(Module->ModuleName, APPINFOSVC_ENCLAVE_IMAGE_NAME) == 0)
            {

                /*
                Author ID for all Windows (not Microsoft) enclaves is 0.

                AuthorID is not impacted by rollovers. It's a unique identifier that is part of the certificate EKUs for 1P and 3P enclaves.

                AuthorID is not specific to the machine, it's specific to the certificate used to sign the enclave.

                */


                //
                // Make sure the AuthorId is zero!!!!  this means Windows-signed (not microsoft signed) according to Akash Trehan
                //

                // skip reporting signing error for now
                if (true)
                {
                    foundValidAppInfoEnclave = true;
                }
                else if (memcmp(Module->AuthorId, ZeroID, sizeof(ZeroID)) == 0)
                {
                    foundValidAppInfoEnclave = true;
                }
                else
                {
                    RETURN_HR(E_FAIL);
                }
            }

            ReportSizeRemaining -= Module->Header.Size;
            PkgSizeRemaining -= Module->Header.Size;

            if (ReportSizeRemaining > 0)
            {

                if (ReportSizeRemaining < sizeof(VBS_ENCLAVE_REPORT_MODULE))
                {
                    RETURN_HR(E_FAIL);
                }

                Module = (VBS_ENCLAVE_REPORT_MODULE*)((PUCHAR)Module + Module->Header.Size);
            }
        }

        if (SystemModulePresent == FALSE)
        {
            RETURN_HR(E_FAIL);
        }

        if (!foundValidAppInfoEnclave)
        {
            RETURN_HR(E_FAIL);
        }

        if (PkgSizeRemaining < PkgHeader->SignatureSize)
        {
            RETURN_HR(E_FAIL);
        }

        return S_OK;
    }

    std::vector<uint8_t> MakePackagedEnclaveIdentityOwnerId(const std::vector<uint8_t>& secureId, const std::wstring& packageFamilyName)
    {
        // PRETEND THIS CODE IS IN DAX
        // 
        // Merge secure id app identity
        //auto secureId = GetSecureId();
        auto bufferIn = std::vector<uint8_t>(secureId.size() + packageFamilyName.size());
        //memcpy(bufferIn.data(), secureId.data(), secureId.size());
        //memcpy(bufferIn.data() + secureId.size(), secureId.data(), secureId.size());

        auto dst = bufferIn.begin();
        std::copy(secureId.begin(), secureId.end(), dst);

        dst += secureId.size();
#pragma warning(push)
#pragma warning(disable : 4244)
        // todo:jw obviously this std::copy is an oof lol
        std::copy(packageFamilyName.begin(), packageFamilyName.end(), dst);
#pragma warning(pop)

        auto bufferOut = std::vector<uint8_t>(SUPPORT_SHARED_HASH_SIZE_BYTES);
        THROW_IF_FAILED(veil::vtl1::cypto::HashData(bufferIn.data(), (ULONG)bufferIn.size(), bufferOut.data()));
        return bufferOut;
    }

    HRESULT ValidatePackagedEnclaveIdentityProof(_Inout_ veil::any::implementation::args::ValidatePackagedEnclaveIdentityProof* params)
        try
    {
        auto actualOwnerId = veil::vtl1::enclave_interface::owner_id();

        // 1. validate app identity matches hardcoded value
        {
            auto userId = std::vector<uint8_t>(params->userIdByteCount); // really secureId
            memcpy(userId.data(), params->userId, userId.size());

            // Check each allowed family
            bool foundMatch = false;
            for (const auto& allowedFamily : veil::vtl1::enclave_interface::config::g_allowedPackageFamilyNames)
            {
                auto expectedOwnerId = MakePackagedEnclaveIdentityOwnerId(userId, allowedFamily.c_str());

                foundMatch = memcmp(actualOwnerId.data(), expectedOwnerId.data(), expectedOwnerId.size()) == 0;
                if (foundMatch)
                {
                    break;
                }
            }

            THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_INSTALL_PACKAGE_INVALID), !foundMatch);
        }

        // 2. validate ownerId blob from report matches 'this' enclave ownerId
        {
            //auto report = ()
            auto expectedChallenge = enclave_handles::consume_challenge(CHALLENGE_PURPOSE__ENCLAVE_IDENTITY_ATTESTATION);
            //THROW_IF_FAILED(x(params->proof, expectedChallenge.data(), ownerId.data()));
            THROW_IF_FAILED(x(params->proof, actualOwnerId.data(), expectedChallenge.data()));
        }

        // 3. validate instancing
        // std::vector<std::wstring> g_allowedPackageFamilyNames;
        // std::function<HRESULT(std::span<const veil::vtl1::enclave_interface::EnclaveInfo>)> g_instancingEnforcementCallback;
        auto lock = 1; //todo:jw get from SK
        lock++;
        std::vector<veil::vtl1::enclave_interface::enclave_info> otherEnclaveInstances; //todo:jw get from SK
        THROW_IF_FAILED(veil::vtl1::enclave_interface::config::g_instancingEnforcementCallback(otherEnclaveInstances));
        lock--;

        // Unlock the enclave
        veil::vtl1::enclave_interface::config::g_isUnlocked = true;

        return S_OK;
    }
    CATCH_RETURN()
    
   HRESULT retrieve_enclave_error_for_thread(_Inout_ veil::any::implementation::args::retrieve_enclave_error_for_thread* params)
        try
    {
        (void)params;

        return S_OK;
    }
    CATCH_RETURN()


        int x2 = 5;

    HRESULT register_callbacks(_Inout_ veil::any::implementation::args::register_callbacks* params)
        try
    {
        static int i = 0;
        if (i == 1)
            THROW_HR(E_INVALIDARG);
        i++;
        ::veil::vtl1::implementation::register_callback(params->callbackAddresses);
        return S_OK;
    }
    CATCH_RETURN()
}
