// Copyright (c) Microsoft Corporation. All rights reserved.

#pragma once

// Brought over from OS.2020\onecore\ds\secrity\enclave\inc\Vtl1MutualAuth.h and lightly modified

#include <array>
#include <vector>
#include <set>
#include <span>

#include <enclaveium.h>
#include <winenclaveapi.h>

#ifndef STATUS_AUTH_TAG_MISMATCH
#define STATUS_AUTH_TAG_MISMATCH ((NTSTATUS)0xC000A002L)
#endif

namespace Vtl1MutualAuth
{

struct SessionChallenge
{
    static constexpr size_t c_challengeSize = 24;

    const std::array<BYTE, 10> header = {"challenge"};
    std::array<BYTE, c_challengeSize> challenge;
    PS_TRUSTLET_TKSESSION_ID sessionId;

    std::vector<BYTE> ToVector() const
    {
        std::vector<BYTE> buffer(sizeof(SessionChallenge));
        size_t index = 0;

        memcpy(buffer.data() + index, header.data(), header.size());
        index += header.size();

        memcpy(buffer.data() + index, challenge.data(), challenge.size());
        index += challenge.size();

        memcpy(buffer.data() + index, &sessionId, sizeof(sessionId));
        index += sizeof(sessionId);

        return buffer;
    }

    static SessionChallenge FromVector(std::span<BYTE const> buffer)
    {
        THROW_HR_IF(NTE_BAD_DATA, buffer.size() != sizeof(SessionChallenge));

        SessionChallenge data{};
        size_t index = 0;

        THROW_HR_IF(NTE_BAD_TYPE, 0 != memcmp(data.header.data(), buffer.data(), data.header.size()));
        index += data.header.size();

        memcpy(data.challenge.data(), buffer.data() + index, data.challenge.size());
        index += data.challenge.size();

        memcpy(&data.sessionId, buffer.data() + index, sizeof(sessionId));
        index += sizeof(sessionId);

        return data;
    }
};

struct AttestationData
{
    static constexpr size_t c_challengeSize = SessionChallenge::c_challengeSize;
    static constexpr size_t c_symmetricSecretSize = 32;

    const std::array<BYTE, 8> header = {"attest"};
    std::array<BYTE, c_challengeSize> challenge;
    std::array<BYTE, c_symmetricSecretSize> symmetricSecret;

    std::vector<BYTE> ToVector()
    {
        std::vector<BYTE> buffer(sizeof(AttestationData));
        size_t index = 0;

        memcpy(buffer.data() + index, header.data(), header.size());
        index += header.size();

        memcpy(buffer.data() + index, challenge.data(), challenge.size());
        index += challenge.size();

        memcpy(buffer.data() + index, symmetricSecret.data(), symmetricSecret.size());
        index += symmetricSecret.size();

        return buffer;
    }

    static AttestationData FromVector(std::span<BYTE const> buffer)
    {
        THROW_HR_IF(NTE_BAD_DATA, buffer.size() != sizeof(AttestationData));

        AttestationData data{};
        size_t index = 0;

        THROW_HR_IF(NTE_BAD_TYPE, 0 != memcmp(data.header.data(), buffer.data(), data.header.size()));
        index += data.header.size();

        memcpy(data.challenge.data(), buffer.data() + index, data.challenge.size());
        index += data.challenge.size();

        memcpy(data.symmetricSecret.data(), buffer.data() + index, data.symmetricSecret.size());
        index += data.symmetricSecret.size();

        return data;
    }
};
static_assert(sizeof(AttestationData) == ENCLAVE_REPORT_DATA_LENGTH);

class MutualAuth
{
protected:
    // This is an AES-GCM key a derived class needs to set
    wil::unique_bcrypt_key m_symmetricKey;

    virtual ULONG64 GetMaxNonce() const
    {
        return c_maxEncryptNonce;
    }

private:
    // There is a nonce for inititator and one for responder. Initiator will start at 0 and use even numbers,
    // while responder will start at 1 and use odd numbers. The nonce will be in the message. Each party will
    // increment its own nonce and keep track of nonces received. The nonces should be unique for each session.
    // There is a limit to the amount of operations allowed per session (tracked by the nonces), if exceeded,
    // the operation will fail with HRESULT_FROM_WIN32(ERROR_TOO_MANY_SECRETS).
    static constexpr ULONG64 c_maxEncryptNonce = 50000;
    ULONG64 m_encryptNonce;
    std::set<ULONG64> m_decryptNonces{};
    wil::srwlock m_lock{};

    static constexpr size_t c_tagBufferSizeAESGCM = 16;
    static constexpr size_t c_nonceSizeAESGCM = 12;

public:
    MutualAuth(bool initiator) : m_encryptNonce(initiator ? 0 : 1)
    {
    }
    ~MutualAuth()
    {
    }

    void reset()
    {
        m_symmetricKey.reset();
        m_encryptNonce = m_encryptNonce % 2;
        m_decryptNonces.clear();
    }

    HRESULT EncryptData(const std::vector<BYTE>& plaintext, _Inout_ std::vector<BYTE>& ciphertext)
    {
        auto lock = m_lock.lock_exclusive();

        RETURN_HR_IF(HRESULT_FROM_WIN32(ERROR_TOO_MANY_SECRETS), m_encryptNonce > GetMaxNonce());

        std::vector<BYTE> tagBuffer(c_tagBufferSizeAESGCM);

        // Fill with 0s and add nonce value towards the end of the buffer
        std::array<BYTE, c_nonceSizeAESGCM> nonceBuffer = {0};
        memcpy(&nonceBuffer[c_nonceSizeAESGCM - sizeof(m_encryptNonce)], reinterpret_cast<PBYTE>(&m_encryptNonce), sizeof(m_encryptNonce));

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO cipherInfo{};
        BCRYPT_INIT_AUTH_MODE_INFO(cipherInfo);
        cipherInfo.pbNonce = nonceBuffer.data();
        cipherInfo.cbNonce = sizeof(nonceBuffer);
        cipherInfo.pbTag = tagBuffer.data();
        cipherInfo.cbTag = static_cast<ULONG>(tagBuffer.size());

        // In AES-GCM ciphertext and plaintext lengths are the same
        std::vector<BYTE> output(plaintext.size());
        ULONG outputSize{};
        RETURN_IF_NTSTATUS_FAILED(BCryptEncrypt(
            m_symmetricKey.get(),
            const_cast<PBYTE>(plaintext.data()),
            static_cast<ULONG>(plaintext.size()),
            &cipherInfo,
            nullptr,
            0,
            output.data(),
            static_cast<ULONG>(output.size()),
            &outputSize,
            0));

        ciphertext.clear();
        ciphertext.insert(
            ciphertext.end(), reinterpret_cast<BYTE*>(&m_encryptNonce), reinterpret_cast<BYTE*>(&m_encryptNonce) + sizeof(m_encryptNonce));
        ciphertext.insert(ciphertext.end(), output.begin(), output.end());
        ciphertext.insert(ciphertext.end(), tagBuffer.begin(), tagBuffer.end());

        m_encryptNonce = m_encryptNonce + 2;

        return S_OK;
    }

    HRESULT DecryptData(const std::vector<BYTE>& ciphertext, _Inout_ std::vector<BYTE>& plaintext)
    {
        auto lock = m_lock.lock_exclusive();

        // Make sure we don't underflow when removing the nonce (ULONG64) and the tag (c_tagBufferSizeAESGCM)
        RETURN_HR_IF(NTE_BAD_DATA, ciphertext.size() < sizeof(ULONG64) + c_tagBufferSizeAESGCM);

        // Nonce is at the beginning of the ciphertext, get/remove it
        ULONG64 nonce = *reinterpret_cast<const UNALIGNED ULONG64*>(ciphertext.data());
        RETURN_HR_IF(NTE_EXISTS, m_decryptNonces.find(nonce) != m_decryptNonces.end());
        const std::vector<BYTE> inputNoNonce(ciphertext.begin() + sizeof(nonce), ciphertext.end());

        // Tag is at the end of the ciphertext, get/remove it
        std::vector<BYTE> tagBuffer(inputNoNonce.end() - c_tagBufferSizeAESGCM, inputNoNonce.end());
        const std::vector<BYTE> inputNoTag(inputNoNonce.begin(), inputNoNonce.end() - tagBuffer.size());

        // Fill with 0s and put the nonce value at the end of the buffer
        std::array<BYTE, c_nonceSizeAESGCM> nonceBuffer = {0};
        static_assert(c_nonceSizeAESGCM >= sizeof(nonce));
        memcpy(&nonceBuffer[c_nonceSizeAESGCM - sizeof(nonce)], reinterpret_cast<PBYTE>(&nonce), sizeof(nonce));

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO cipherInfo{};
        BCRYPT_INIT_AUTH_MODE_INFO(cipherInfo);
        cipherInfo.pbNonce = nonceBuffer.data();
        cipherInfo.cbNonce = sizeof(nonceBuffer);
        cipherInfo.pbTag = tagBuffer.data();
        cipherInfo.cbTag = static_cast<ULONG>(tagBuffer.size());

        // In AES-GCM ciphertext and plaintext lengths are the same
        std::vector<BYTE> output(inputNoTag.size());
        ULONG outputSize{};
        // Special case return from BCryptDecrypt due to mistranslation of NTSTATUS to Dos Error
        // for STATUS_AUTH_TAG_MISMATCH (0xC000A002L) to ERROR_CRC (0x17) by RtlNtStatusToDosError
        NTSTATUS status = BCryptDecrypt(
            m_symmetricKey.get(),
            const_cast<PBYTE>(inputNoTag.data()),
            static_cast<ULONG>(inputNoTag.size()),
            &cipherInfo,
            nullptr,
            0,
            output.data(),
            static_cast<ULONG>(output.size()),
            &outputSize,
            0);

        RETURN_HR_IF((HRESULT)STATUS_AUTH_TAG_MISMATCH, status == STATUS_AUTH_TAG_MISMATCH);
        RETURN_IF_NTSTATUS_FAILED(status);

        m_decryptNonces.insert(nonce);
        plaintext = std::move(output);

        return S_OK;
    }
};

} // namespace Vtl1MutualAuth

namespace enclave_encryption
{
    static constexpr size_t c_tagBufferSizeAESGCM = 16;
    static constexpr size_t c_nonceSizeAESGCM = 12;

    inline HRESULT decrypt_data(BCRYPT_KEY_HANDLE symmetricKey, const std::vector<BYTE>& ciphertext, _Inout_ std::vector<BYTE>& plaintext)
    {
        // auto lock = m_lock.lock_exclusive();  //todo:jw lock why?

        // Make sure we don't underflow when removing the nonce (ULONG64) and the tag (c_tagBufferSizeAESGCM)
        RETURN_HR_IF(NTE_BAD_DATA, ciphertext.size() < sizeof(ULONG64) + c_tagBufferSizeAESGCM);

        // Nonce is at the beginning of the ciphertext, get/remove it
        ULONG64 nonce = *reinterpret_cast<const UNALIGNED ULONG64*>(ciphertext.data());
        //RETURN_HR_IF(NTE_EXISTS, m_decryptNonces.find(nonce) != m_decryptNonces.end());
        const std::vector<BYTE> inputNoNonce(ciphertext.begin() + sizeof(nonce), ciphertext.end());

        // Tag is at the end of the ciphertext, get/remove it
        std::vector<BYTE> tagBuffer(inputNoNonce.end() - c_tagBufferSizeAESGCM, inputNoNonce.end());
        const std::vector<BYTE> inputNoTag(inputNoNonce.begin(), inputNoNonce.end() - tagBuffer.size());

        // Fill with 0s and put the nonce value at the end of the buffer
        std::array<BYTE, c_nonceSizeAESGCM> nonceBuffer = { 0 };
        static_assert(c_nonceSizeAESGCM >= sizeof(nonce));
        memcpy(&nonceBuffer[c_nonceSizeAESGCM - sizeof(nonce)], reinterpret_cast<PBYTE>(&nonce), sizeof(nonce));

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO cipherInfo{};
        BCRYPT_INIT_AUTH_MODE_INFO(cipherInfo);
        cipherInfo.pbNonce = nonceBuffer.data();
        cipherInfo.cbNonce = sizeof(nonceBuffer);
        cipherInfo.pbTag = tagBuffer.data();
        cipherInfo.cbTag = static_cast<ULONG>(tagBuffer.size());

        // In AES-GCM ciphertext and plaintext lengths are the same
        std::vector<BYTE> output(inputNoTag.size());
        ULONG outputSize{};
        // Special case return from BCryptDecrypt due to mistranslation of NTSTATUS to Dos Error
        // for STATUS_AUTH_TAG_MISMATCH (0xC000A002L) to ERROR_CRC (0x17) by RtlNtStatusToDosError
        NTSTATUS status = BCryptDecrypt(
            symmetricKey,
            const_cast<PBYTE>(inputNoTag.data()),
            static_cast<ULONG>(inputNoTag.size()),
            &cipherInfo,
            nullptr,
            0,
            output.data(),
            static_cast<ULONG>(output.size()),
            &outputSize,
            0);

        RETURN_HR_IF((HRESULT)STATUS_AUTH_TAG_MISMATCH, status == STATUS_AUTH_TAG_MISMATCH);
        RETURN_IF_NTSTATUS_FAILED(status);

        //m_decryptNonces.insert(nonce);
        plaintext = std::move(output);

        return S_OK;
    }
}
