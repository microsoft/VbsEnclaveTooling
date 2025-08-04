// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <span>
#include <wil/stl.h>
#include <gsl/gsl_util>

namespace veil::vtl1::crypto
{

    //
    // Constants
    //
    constexpr auto SYMMETRIC_KEY_SIZE_BYTES = 32; // AES-GCM
    constexpr auto DH_KEY_SIZE_BITS = 384;        // ECDH P-384
    constexpr auto NONCE_SIZE = 12;
    constexpr auto TAG_SIZE = 16;

    constexpr auto zero_nonce = std::array<uint8_t, NONCE_SIZE>{0};

    //
    // Types
    //
    using symmetric_key_bytes = std::array<uint8_t, SYMMETRIC_KEY_SIZE_BYTES>;

    //
    // Functions
    //
    [[nodiscard]] inline HRESULT hr_from_bcrypt_status(NTSTATUS status) noexcept
    {
#ifdef STATUS_AUTH_TAG_MISMATCH
        constexpr auto status_auth_tag_mismatch = STATUS_AUTH_TAG_MISMATCH;
#else
        constexpr auto status_auth_tag_mismatch = (NTSTATUS)0xC000A002L;
#endif
        // RtlNtStatusToDosError converts STATUS_AUTH_TAG_MISMATCH to the very misleading
        // HRESULT_FROM_WIN32(ERROR_CRC). Special-case that error for BCryptDecrypt and preserve
        // it as itself.
        RETURN_HR_IF_EXPECTED((HRESULT)status_auth_tag_mismatch, status == status_auth_tag_mismatch);
        RETURN_IF_NTSTATUS_FAILED_EXPECTED(status);
        return S_OK;
    }

    [[nodiscard]] inline std::array<uint8_t, NONCE_SIZE> make_nonce_buffer_from_number(ULONG64 nonce)
    {
        // Fill with 0s and add nonce value towards the end of the buffer
        std::array<uint8_t, NONCE_SIZE> nonceBuffer = {0};

        // Effectively:
        //  memcpy(&nonceBuffer[NONCE_SIZE - sizeof(nonce)], reinterpret_cast<const uint8_t*>(&nonce), sizeof(nonce));
        auto pNonce = reinterpret_cast<uint8_t*>(&nonce);
        std::copy(pNonce, pNonce + sizeof(nonce), nonceBuffer.end() - sizeof(nonce));
        return nonceBuffer;
    }

    inline BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO make_BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO(std::span<uint8_t const> nonce, std::span<uint8_t const> tag)
    {
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO cipherInfo {};
        BCRYPT_INIT_AUTH_MODE_INFO(cipherInfo);
        cipherInfo.pbNonce = const_cast<UCHAR*>(nonce.data());
        cipherInfo.cbNonce = gsl::narrow_cast<ULONG>(nonce.size());;
        cipherInfo.pbTag = const_cast<UCHAR*>(tag.data());
        cipherInfo.cbTag = gsl::narrow_cast<ULONG>(tag.size());
        return cipherInfo;
    }

    template <size_t N>
    inline std::array<uint8_t, N> generate_random()
    {
        std::array<uint8_t, N> buffer;
        THROW_IF_FAILED(HRESULT_FROM_NT(BCryptGenRandom(nullptr, buffer.data(), static_cast<ULONG>(buffer.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG)));
        return buffer;
    }

    template <size_t N>
    inline HRESULT generate_random(_Out_ uint8_t (&buffer)[N])
    {
        RETURN_IF_FAILED(HRESULT_FROM_NT(BCryptGenRandom(nullptr, buffer, N, BCRYPT_USE_SYSTEM_PREFERRED_RNG)));
        return S_OK;
    }

    inline HRESULT generate_random(_Out_ symmetric_key_bytes& symmetricKeyBytes)
    {
        RETURN_IF_FAILED(HRESULT_FROM_NT(BCryptGenRandom(nullptr, symmetricKeyBytes.data(), static_cast<ULONG>(symmetricKeyBytes.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG)));
        return S_OK;
    }

    inline HRESULT generate_symmetric_key_bytes(_Out_ symmetric_key_bytes& symmetricKeyBytes)
    {
        RETURN_IF_FAILED(generate_random(symmetricKeyBytes));
        return S_OK;
    }

    inline symmetric_key_bytes generate_symmetric_key_bytes()
    {
        symmetric_key_bytes keyBytes;
        THROW_IF_FAILED(veil::vtl1::crypto::generate_symmetric_key_bytes(keyBytes));
        return keyBytes;
    }

    inline HRESULT create_symmetric_key(std::span<uint8_t const> symmetricKeyBytes, _Out_ wil::unique_bcrypt_key& symmetricKey)
    {
        RETURN_IF_NTSTATUS_FAILED(BCryptGenerateSymmetricKey(
            BCRYPT_AES_GCM_ALG_HANDLE,
            &symmetricKey,
            nullptr,
            0,
            const_cast<uint8_t*>(symmetricKeyBytes.data()),
            gsl::narrow_cast<ULONG>(symmetricKeyBytes.size()),
            0));

        return S_OK;
    }

    inline wil::unique_bcrypt_key create_symmetric_key(std::span<uint8_t const> keyBytes)
    {
        wil::unique_bcrypt_key symmetricKey;
        THROW_IF_FAILED(veil::vtl1::crypto::create_symmetric_key(keyBytes, symmetricKey));
        return symmetricKey;
    }

    inline wil::unique_bcrypt_key generate_symmetric_key()
    {
        symmetric_key_bytes keyBytes;
        THROW_IF_FAILED(veil::vtl1::crypto::generate_symmetric_key_bytes(keyBytes));
        wil::unique_bcrypt_key symmetricKey;
        THROW_IF_FAILED(veil::vtl1::crypto::create_symmetric_key(keyBytes, symmetricKey));
        return symmetricKey;
    }

    //
    // BCrypt key things
    //
    inline wil::unique_bcrypt_key bcrypt_import_key_pair(std::span<uint8_t const> keyBytes)
    {
        wil::unique_bcrypt_key key;
        THROW_IF_NTSTATUS_FAILED(::BCryptImportKeyPair(
            BCRYPT_ECDH_P384_ALG_HANDLE,
            nullptr,
            BCRYPT_ECCPUBLIC_BLOB,
            &key,
            const_cast<PUCHAR>(keyBytes.data()),
            gsl::narrow_cast<ULONG>(keyBytes.size()),
            0));
        return key;
    }

    inline std::vector<uint8_t> bcrypt_export_public_key(BCRYPT_KEY_HANDLE key)
    {
        ULONG keySize = 0;
        THROW_IF_NTSTATUS_FAILED(BCryptExportKey(key, nullptr, BCRYPT_ECCPUBLIC_BLOB, nullptr, 0, &keySize, 0));

        std::vector<uint8_t> keyBytes(keySize);
        THROW_IF_NTSTATUS_FAILED(BCryptExportKey(key, nullptr, BCRYPT_ECCPUBLIC_BLOB, keyBytes.data(), keySize, &keySize, 0));
        return keyBytes;
    }

    inline wil::unique_bcrypt_key bcrypt_generate_ecdh_key_pair(BCRYPT_ALG_HANDLE algorithm)
    {
        wil::unique_bcrypt_key ecdhKeyPair;
        THROW_IF_NTSTATUS_FAILED(BCryptGenerateKeyPair(algorithm, &ecdhKeyPair, veil::vtl1::crypto::DH_KEY_SIZE_BITS, 0));
        THROW_IF_NTSTATUS_FAILED(BCryptFinalizeKeyPair(ecdhKeyPair.get(), 0));
        return ecdhKeyPair;
    }

    inline wil::unique_bcrypt_key bcrypt_derive_symmetric_key(BCRYPT_KEY_HANDLE privateKey, BCRYPT_KEY_HANDLE publicKey)
    {
        // Determine ECDH shared secret
        wil::unique_bcrypt_secret ecdhSecret;
        THROW_IF_NTSTATUS_FAILED(BCryptSecretAgreement(privateKey, publicKey, &ecdhSecret, 0));

        // Derive a key from private and public keys
        ULONG derivedKeySize = 0;
        THROW_IF_NTSTATUS_FAILED(BCryptDeriveKey(ecdhSecret.get(), BCRYPT_KDF_RAW_SECRET, nullptr, nullptr, 0, &derivedKeySize, 0));
        wil::secure_vector<uint8_t> derivedKeyBytes(derivedKeySize);
        THROW_IF_NTSTATUS_FAILED(BCryptDeriveKey(ecdhSecret.get(), BCRYPT_KDF_RAW_SECRET, nullptr, derivedKeyBytes.data(), derivedKeySize, &derivedKeySize, 0));
        wil::unique_bcrypt_key derivedKey;
        THROW_IF_NTSTATUS_FAILED(BCryptGenerateSymmetricKey(BCRYPT_AES_GCM_ALG_HANDLE, &derivedKey, nullptr, 0, derivedKeyBytes.data(), derivedKeySize, 0));
        return derivedKey;
    }

    //
    // Encrypt (with cipherinfo)
    //
    inline wil::secure_vector<uint8_t> encrypt(BCRYPT_KEY_HANDLE symmetricKey, std::span<uint8_t const> plaintext, const BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO* cipherInfo)
    {
        // In AES-GCM ciphertext and plaintext lengths are the same
        wil::secure_vector<uint8_t> ciphertext(plaintext.size());

        ULONG ciphertextSize {};
        NTSTATUS status = BCryptEncrypt(
            symmetricKey,
            const_cast<PBYTE>(plaintext.data()),
            gsl::narrow_cast<ULONG>(plaintext.size()),
            const_cast<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO*>(cipherInfo),
            nullptr,
            0,
            ciphertext.data(),
            gsl::narrow_cast<ULONG>(ciphertext.size()),
            &ciphertextSize,
            0);

        THROW_IF_FAILED(hr_from_bcrypt_status(status));

        return ciphertext;
    }

    inline wil::secure_vector<uint8_t> decrypt(BCRYPT_KEY_HANDLE symmetricKey, std::span<uint8_t const> ciphertext, const BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO* cipherInfo)
    {
        // In AES-GCM ciphertext and plaintext lengths are the same
        wil::secure_vector<uint8_t> plaintext(ciphertext.size());
        ULONG plaintextSize {};
        NTSTATUS status = BCryptDecrypt(
            symmetricKey,
            const_cast<PBYTE>(ciphertext.data()),
            static_cast<ULONG>(ciphertext.size()),
            const_cast<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO*>(cipherInfo),
            nullptr,
            0,
            plaintext.data(),
            static_cast<ULONG>(plaintext.size()),
            &plaintextSize,
            0);

        THROW_IF_FAILED(hr_from_bcrypt_status(status));

        return plaintext;
    }

    //
    // Encrypt simplified
    //
    inline std::pair<
        wil::secure_vector<uint8_t>,
        std::array<uint8_t, TAG_SIZE>>
        encrypt(BCRYPT_KEY_HANDLE symmetricKey, std::span<uint8_t const> plaintext, std::span<uint8_t const> nonce)
    {
        std::array<uint8_t, TAG_SIZE> tag = {0};
        auto cipherInfo = make_BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO(nonce, tag);
        auto ciphertext = encrypt(symmetricKey, plaintext, &cipherInfo);
        return {ciphertext, tag};
    }

    inline wil::secure_vector<uint8_t> decrypt(BCRYPT_KEY_HANDLE symmetricKey, std::span<uint8_t const> ciphertext, std::span<uint8_t const> nonce, std::span<uint8_t const> tag)
    {
        auto cipherInfo = make_BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO(nonce, tag);
        return decrypt(symmetricKey, ciphertext, &cipherInfo);
    }

    //
    // Encrypt with tag
    //
    inline wil::secure_vector<uint8_t> encrypt_and_tag(BCRYPT_KEY_HANDLE key, std::span<uint8_t const> plaintext, std::span<uint8_t const> nonce)
    {
        // This produces an output containing the {data}{tag:16}. The nonce is always zero.
        uint8_t tag[TAG_SIZE] = {0};

        auto cipherInfo = make_BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO(nonce, tag);

        auto encryptedContent = encrypt(key, plaintext, &cipherInfo);
        encryptedContent.insert(encryptedContent.end(), tag, tag + TAG_SIZE);
        return encryptedContent;
    }

    inline wil::secure_vector<uint8_t> encrypt_and_tag(BCRYPT_KEY_HANDLE key, std::span<uint8_t const> plaintext)
    {
        return encrypt_and_tag(key, plaintext, zero_nonce);
    }

    inline wil::secure_vector<uint8_t> decrypt_and_untag(BCRYPT_KEY_HANDLE key, std::span<uint8_t const> ciphertext, std::span<uint8_t const> nonce)
    {
        // The payload consists of the {data}{tag}. The size of the payload must be at least the size of the tag.
        // This method always uses a zero nonce.
        THROW_HR_IF(E_INVALIDARG, ciphertext.size() < TAG_SIZE);

        auto data = std::span<uint8_t const> {ciphertext.data(), ciphertext.size() - TAG_SIZE};
        auto tag = std::span<uint8_t const> {data.data() + data.size(), TAG_SIZE};

        auto cipherInfo = make_BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO(nonce, tag);

        auto decryptedContent = decrypt(key, data, &cipherInfo);
        return decryptedContent;
    }

    inline wil::secure_vector<uint8_t> decrypt_and_untag(BCRYPT_KEY_HANDLE key, std::span<uint8_t const> ciphertext)
    {
        return decrypt_and_untag(key, ciphertext, zero_nonce);
    }

    //
    // Sealing encryption
    //
    inline wil::secure_vector<uint8_t> seal_data(std::span<const uint8_t> unsealedData, ENCLAVE_SEALING_IDENTITY_POLICY identityPolicy, UINT32 runtimePolicy)
    {
        UINT32 sealedSize = 0;
        THROW_IF_FAILED(::EnclaveSealData(
            unsealedData.data(),
            gsl::narrow_cast<UINT32>(unsealedData.size()),
            identityPolicy,
            runtimePolicy,
            nullptr,
            0,
            &sealedSize));

        auto sealedBytes = wil::secure_vector<uint8_t>(sealedSize);
        THROW_IF_FAILED(::EnclaveSealData(
            unsealedData.data(),
            gsl::narrow_cast<UINT32>(unsealedData.size()),
            identityPolicy,
            runtimePolicy,
            sealedBytes.data(),
            sealedSize,
            &sealedSize));

        return sealedBytes;
    }

    inline std::pair<wil::secure_vector<uint8_t>, UINT32> unseal_data(std::span<uint8_t const> sealedBytes)
    {
        UINT32 unsealedDataSize;
        THROW_IF_FAILED(::EnclaveUnsealData(
            sealedBytes.data(),
            gsl::narrow_cast<UINT32>(sealedBytes.size()),
            nullptr,
            0,
            &unsealedDataSize,
            nullptr,
            nullptr));

        UINT32 unsealingFlags = 0;
        auto unsealedBytes = wil::secure_vector<uint8_t>(unsealedDataSize);
        THROW_IF_FAILED(::EnclaveUnsealData(
            sealedBytes.data(),
            gsl::narrow_cast<UINT32>(sealedBytes.size()),
            unsealedBytes.data(),
            unsealedDataSize,
            &unsealedDataSize,
            nullptr,
            &unsealingFlags));

        return {unsealedBytes, unsealingFlags};
    }
}
