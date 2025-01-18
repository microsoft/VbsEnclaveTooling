// © Microsoft Corporation. All rights reserved.

#include "pch.h"

#include <functional>
#include <map>
#include <vector>

#include <safeint.h>


#include <wil/stl.h>

//#include "shared_enclave.h"
#include "veil_arguments.any.h"

#include "enclave_interface.vtl1.h"
#include "exports.vtl1.h"
#include "mutualauth.vtl1.h"
#include "registered_callbacks.vtl1.h"
#include "threadpool.vtl1.h"
#include "utils.vtl1.h"





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
    HRESULT retrieve_enclave_error_for_thread(_Inout_ veil::any::implementation::args::retrieve_enclave_error_for_thread* params)
        try
    {
        (void)params;

        return S_OK;
    }
    CATCH_RETURN()

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
