// Copyright (c) Microsoft Corporation. All rights reserved.

#pragma once

//#include <iumtypes.h>
//#include <ntenclv.h>

#include <vector>
#include <array>
#include <set>
#include <bitset>
#include <memory>

#include <wil\resource.h>

namespace Vtl1MutualAuth
{

    static constexpr size_t c_maxRequestNonce = 999;
    static constexpr size_t c_maxEncryptedUserKeySize = 9999;

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

    static SessionChallenge FromVector(const std::vector<BYTE> buffer)
    {
        THROW_HR_IF(NTE_BAD_DATA, buffer.size() != sizeof(SessionChallenge));

        SessionChallenge data {};
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
    //static constexpr SIZE_T c_attestationDataVectorSize = sizeof(ATTESTATION_HEADER) + c_challengeSize + c_symmetricSecretSize;
    static constexpr SIZE_T c_attestationDataVectorSize = 99;

    const std::array<BYTE, 8> header = {"attest"};
    std::array<BYTE, c_challengeSize> challenge;
    std::array<BYTE, c_symmetricSecretSize> symmetricSecret;

    const std::vector<BYTE> ToVector()
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

    static AttestationData FromVector(const std::vector<BYTE> buffer)
    {
        THROW_HR_IF(NTE_BAD_DATA, buffer.size() != sizeof(AttestationData));

        AttestationData data {};
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

class MutualAuthOld
{
    protected:
        // This is an AES-GCM key a derived class needs to set
    wil::unique_bcrypt_key m_symmetricKey;

    private:
        // There is a nonce for inititator and one for responder. Initiator will start at 0 and use even numbers,
        // while responder will start at 1 and use odd numbers. The nonce will be in the message. Each party will
        // increment its own nonce and keep track of nonces received. The nonces should be unique for each session.
        // There is a limit to the amount of operations allowed per session (tracked by the nonces), if exceeded,
        // the operation will fail with HRESULT_FROM_WIN32(ERROR_TOO_MANY_SECRETS).
    static constexpr ULONG64 c_maxEncryptNonce = 50000;
    ULONG64 m_encryptNonce;
    std::set<ULONG64> m_decryptNonces {};
    wil::srwlock m_lock {};

    static constexpr size_t c_tagBufferSizeAESGCM = 16;
    static constexpr size_t c_nonceSizeAESGCM = 12;

    public:
    MutualAuthOld(bool initiator) : m_encryptNonce(initiator ? 0 : 1) {}
    ~MutualAuthOld() {}

    HRESULT EncryptData(const std::vector<BYTE>& plaintext, _Inout_ std::vector<BYTE>& ciphertext)
    {
        auto lock = m_lock.lock_exclusive();

        RETURN_HR_IF(HRESULT_FROM_WIN32(ERROR_TOO_MANY_SECRETS), m_encryptNonce > c_maxEncryptNonce);

        std::vector<BYTE> tagBuffer(c_tagBufferSizeAESGCM);

        // Fill with 0s and add nonce value towards the end of the buffer
        std::array<BYTE, c_nonceSizeAESGCM> nonceBuffer = {0};
        memcpy(&nonceBuffer[c_nonceSizeAESGCM - sizeof(m_encryptNonce)], reinterpret_cast<PBYTE>(&m_encryptNonce), sizeof(m_encryptNonce));

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO cipherInfo {};
        BCRYPT_INIT_AUTH_MODE_INFO(cipherInfo);
        cipherInfo.pbNonce = nonceBuffer.data();
        cipherInfo.cbNonce = sizeof(nonceBuffer);
        cipherInfo.pbTag = tagBuffer.data();
        cipherInfo.cbTag = static_cast<ULONG>(tagBuffer.size());

        // In AES-GCM ciphertext and plaintext lengths are the same
        std::vector<BYTE> output(plaintext.size());
        ULONG outputSize {};
        RETURN_IF_NTSTATUS_FAILED(BCryptEncrypt(
            m_symmetricKey.get(), const_cast<PBYTE>(plaintext.data()), static_cast<ULONG>(plaintext.size()), &cipherInfo,
            nullptr, 0, output.data(), static_cast<ULONG>(output.size()), &outputSize, 0));

        ciphertext.clear();
        ciphertext.insert(ciphertext.end(),
            reinterpret_cast<BYTE*>(&m_encryptNonce), reinterpret_cast<BYTE*>(&m_encryptNonce) + sizeof(m_encryptNonce));
        ciphertext.insert(ciphertext.end(), output.begin(), output.end());
        ciphertext.insert(ciphertext.end(), tagBuffer.begin(), tagBuffer.end());

        m_encryptNonce = m_encryptNonce + 2;

        return S_OK;
    }

    HRESULT DecryptData(const std::vector<BYTE>& ciphertext, _Inout_ std::vector<BYTE>& plaintext)
    {
        auto lock = m_lock.lock_exclusive();

        // Nonce is at the beginning of the ciphertext, get/remove it
        RETURN_HR_IF(NTE_BAD_DATA, ciphertext.size() < sizeof(ULONG64));
        ULONG64 nonce = *reinterpret_cast<const ULONG64*>(ciphertext.data());
        RETURN_HR_IF(NTE_EXISTS, m_decryptNonces.find(nonce) != m_decryptNonces.end());
        const std::vector<BYTE> inputNoNonce(ciphertext.begin() + sizeof(nonce), ciphertext.end());

        // Tag is at the end of the ciphertext, get/remove it
        std::vector<BYTE> tagBuffer(inputNoNonce.end() - c_tagBufferSizeAESGCM, inputNoNonce.end());
        const std::vector<BYTE> inputNoTag(inputNoNonce.begin(), inputNoNonce.end() - tagBuffer.size());

        // Fill with 0s and add nonce value towards the end of the buffer
        std::array<BYTE, c_nonceSizeAESGCM> nonceBuffer = {0};
        memcpy(&nonceBuffer[c_nonceSizeAESGCM - sizeof(nonce)], reinterpret_cast<PBYTE>(&nonce), sizeof(nonce));

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO cipherInfo {};
        BCRYPT_INIT_AUTH_MODE_INFO(cipherInfo);
        cipherInfo.pbNonce = nonceBuffer.data();
        cipherInfo.cbNonce = sizeof(nonceBuffer);
        cipherInfo.pbTag = tagBuffer.data();
        cipherInfo.cbTag = static_cast<ULONG>(tagBuffer.size());

        // In AES-GCM ciphertext and plaintext lengths are the same
        std::vector<BYTE> output(inputNoTag.size());
        ULONG outputSize {};
        RETURN_IF_NTSTATUS_FAILED(BCryptDecrypt(
            m_symmetricKey.get(), const_cast<PBYTE>(inputNoTag.data()), static_cast<ULONG>(inputNoTag.size()), &cipherInfo,
            nullptr, 0, output.data(), static_cast<ULONG>(output.size()), &outputSize, 0));

        m_decryptNonces.insert(nonce);
        plaintext = std::move(output);

        return S_OK;
    }
};

class MutualAuth
{
    protected:
        // This is an AES-GCM key a derived class needs to set
    wil::unique_bcrypt_key m_symmetricKey;

    private:
        // Nonces details:
        // The requestor will increment its nonce value (initialize at 0) and used the updated as requestor nonce.
        // The requestor nonce will be in the messageBlob.
        // The responder will flip an unused bit of the requestor nonce and use that as responder nonce.
        // The responder will keep track of the requestors nonces to guarantee no message is replayed.
        // The responder nonce doesn't need to be in the message blob.
        // The requestor will confirm that the response corresponds to the request (via nonce)

    const bool m_requestor;

    static constexpr ULONG64 c_maxRequestNonce = 100000;
    static constexpr ULONG64 c_responderBitFlip = 0x80000000;
    static_assert(c_maxRequestNonce < c_responderBitFlip);

    ULONG64 m_requestNonce {};
    std::unique_ptr<std::bitset<c_maxRequestNonce>> m_responderSeenNonces {};
    wil::srwlock m_lock {};

    static constexpr size_t c_tagBufferSizeAESGCM = 16;
    static constexpr size_t c_nonceSizeAESGCM = 12;

    public:
    MutualAuth(bool requestor) : m_requestor(requestor), m_requestNonce(0)
    {
        m_responderSeenNonces = std::make_unique<std::bitset<c_maxRequestNonce>>();
    }
    ~MutualAuth() {}

    HRESULT EncryptRequest(const std::vector<BYTE>& plaintext, _Out_ ULONG64* requestNonce, _Inout_ std::vector<BYTE>& ciphertext)
    {
        RETURN_HR_IF(NTE_NOT_SUPPORTED, !m_requestor);
        ULONG64 localNonce = InterlockedIncrement64(reinterpret_cast<LONG64*>(&m_requestNonce));
        RETURN_HR_IF(HRESULT_FROM_WIN32(ERROR_TOO_MANY_SECRETS), localNonce >= c_maxRequestNonce);

        RETURN_IF_FAILED(EncryptData(plaintext, localNonce, ciphertext));
        *requestNonce = localNonce;

        return S_OK;
    }

    HRESULT EncryptResponse(const std::vector<BYTE>& plaintext, const ULONG64 requestNonce, _Inout_ std::vector<BYTE>& ciphertext)
    {
        RETURN_HR_IF(NTE_NOT_SUPPORTED, m_requestor);
        const ULONG64 localNonce = requestNonce ^ c_responderBitFlip;
        RETURN_IF_FAILED(EncryptData(plaintext, localNonce, ciphertext));

        return S_OK;
    }

    HRESULT DecryptRequest(const std::vector<BYTE>& ciphertext, _Out_ ULONG64* requestNonce, _Inout_ std::vector<BYTE>& plaintext)
    {
        RETURN_HR_IF(NTE_NOT_SUPPORTED, m_requestor);
        // Nonce is at the beginning of the ciphertext
        RETURN_HR_IF(NTE_BAD_DATA, ciphertext.size() < sizeof(ULONG64));
        ULONG64 localNonce = *reinterpret_cast<const ULONG64*>(ciphertext.data());
        RETURN_HR_IF(HRESULT_FROM_WIN32(ERROR_TOO_MANY_SECRETS), localNonce >= c_maxRequestNonce);
        {
            auto lock = m_lock.lock_exclusive();

            RETURN_HR_IF(NTE_EXISTS, m_responderSeenNonces->test(static_cast<size_t>(localNonce)));
            m_responderSeenNonces->set(static_cast<size_t>(localNonce));
        }

        const std::vector<BYTE> ciphertextNoNonce(ciphertext.begin() + sizeof(localNonce), ciphertext.end());

        RETURN_IF_FAILED(DecryptData(ciphertextNoNonce, localNonce, plaintext));
        *requestNonce = localNonce;

        return S_OK;
    }

    HRESULT DecryptResponse(const std::vector<BYTE>& ciphertext, const ULONG64 requestNonce, _Inout_ std::vector<BYTE>& plaintext)
    {
        RETURN_HR_IF(NTE_NOT_SUPPORTED, !m_requestor);
        const ULONG64 localNonce = requestNonce ^ c_responderBitFlip;
        RETURN_IF_FAILED(DecryptData(ciphertext, localNonce, plaintext));

        return S_OK;
    }

    private:
    HRESULT EncryptData(const std::vector<BYTE>& plaintext, const ULONG64 nonce, _Inout_ std::vector<BYTE>& ciphertext) const
    {
        // Fill with 0s and add nonce value towards the end of the buffer
        std::array<BYTE, c_nonceSizeAESGCM> nonceBuffer = {0};
        memcpy(&nonceBuffer[c_nonceSizeAESGCM - sizeof(nonce)], reinterpret_cast<const BYTE*>(&nonce), sizeof(nonce));

        std::vector<BYTE> tagBuffer(c_tagBufferSizeAESGCM);

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO cipherInfo {};
        BCRYPT_INIT_AUTH_MODE_INFO(cipherInfo);
        cipherInfo.pbNonce = nonceBuffer.data();
        cipherInfo.cbNonce = sizeof(nonceBuffer);
        cipherInfo.pbTag = tagBuffer.data();
        cipherInfo.cbTag = static_cast<ULONG>(tagBuffer.size());

        // In AES-GCM ciphertext and plaintext lengths are the same
        std::vector<BYTE> output(plaintext.size());
        ULONG outputSize {};
        RETURN_IF_NTSTATUS_FAILED(BCryptEncrypt(
            m_symmetricKey.get(), const_cast<PBYTE>(plaintext.data()), static_cast<ULONG>(plaintext.size()), &cipherInfo,
            nullptr, 0, output.data(), static_cast<ULONG>(output.size()), &outputSize, 0));

        ciphertext.clear();
        if (m_requestor)
        {
            ciphertext.insert(ciphertext.end(),
                reinterpret_cast<const BYTE*>(&nonce), reinterpret_cast<const BYTE*>(&nonce) + sizeof(nonce));
        }
        ciphertext.insert(ciphertext.end(), output.begin(), output.end());
        ciphertext.insert(ciphertext.end(), tagBuffer.begin(), tagBuffer.end());

        return S_OK;
    }

    HRESULT DecryptData(const std::vector<BYTE>& ciphertext, const ULONG64 nonce, _Inout_ std::vector<BYTE>& plaintext)
    {
        // Fill with 0s and add nonce value towards the end of the buffer
        std::array<BYTE, c_nonceSizeAESGCM> nonceBuffer = {0};
        memcpy(&nonceBuffer[c_nonceSizeAESGCM - sizeof(nonce)], reinterpret_cast<const BYTE*>(&nonce), sizeof(nonce));

        // Tag is at the end of the ciphertext, get/remove it
        RETURN_HR_IF(NTE_BAD_DATA, ciphertext.size() < c_tagBufferSizeAESGCM);
        std::vector<BYTE> tagBuffer(ciphertext.end() - c_tagBufferSizeAESGCM, ciphertext.end());
        const std::vector<BYTE> inputNoTag(ciphertext.begin(), ciphertext.end() - tagBuffer.size());

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO cipherInfo {};
        BCRYPT_INIT_AUTH_MODE_INFO(cipherInfo);
        cipherInfo.pbNonce = nonceBuffer.data();
        cipherInfo.cbNonce = sizeof(nonceBuffer);
        cipherInfo.pbTag = tagBuffer.data();
        cipherInfo.cbTag = static_cast<ULONG>(tagBuffer.size());

        // In AES-GCM ciphertext and plaintext lengths are the same
        std::vector<BYTE> output(inputNoTag.size());
        ULONG outputSize {};
        RETURN_IF_NTSTATUS_FAILED(BCryptDecrypt(
            m_symmetricKey.get(), const_cast<PBYTE>(inputNoTag.data()), static_cast<ULONG>(inputNoTag.size()), &cipherInfo,
            nullptr, 0, output.data(), static_cast<ULONG>(output.size()), &outputSize, 0));

        plaintext = std::move(output);

        return S_OK;
    }
};

} /*Vtl1MutualAuth*/
