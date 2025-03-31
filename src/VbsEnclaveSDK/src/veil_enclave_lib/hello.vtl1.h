// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <span>

#include <gsl/gsl_util>
#include <wil/stl.h>

#include "veil_arguments.any.h"
#include "hello.any.h"
#include "utils.any.h"

#include "crypto.vtl1.h"
#include "future.vtl1.h"
#include "memory.vtl1.h"
#include "ngc.vtl1.h"
#include "object_table.vtl1.h"
#include "registered_callbacks.vtl1.h"
#include "utils.vtl1.h"
#include "vtl0_functions.vtl1.h"

//
// TODO: SECURITY
// 
// Call-in and callback data/buffer memcpying, bounds-checks + TOCTOU
// safety is missing and waiting for the .edl tooling codegen work
// implemented & consumed.
//

// Keys
//
//    Name          | Type      | Description
//    ------------- | --------- | -----------------------------------------------------
//    USER_KEY      | symmetric | The user's encryption key
//    SESSION_KEY   | symmetric | The key used for this session's secure the communication with Hello/NGC
//    HELLO_KEY     | pair      | An NGC key created by the user (but 'priv' half is unexportable from NGC's KSP)
//    EPHEMERAL_KEY | pair      | The key used to derive the KEK (along with HELLO_KEY)
//    KEK           | symmetric | The key used to encrypt the USER_KEY
//
//
//
// Creation flow: veil::vtl1::hello::conceal_encryption_key_with_hello
//
//    NGC    Host  Enclave   CallInfo
//    --     ---   -------   ---------------------------------------------------------------------------
//    .       |       .         
//    |<------|       .         Call NCryptCreatePersistedKey
//    |       .       .         Create HELLO_KEY 'pair'
//    |------>|       .             return handle
//    .       |------>|         Send HELLO_KEY into enclave
//    .       .       |         Generate USER_KEY (symmetric) for encryption
//    .       .       |
//    .       .       |         [STEP 1] Secure channel
//    .       .       |             Generate SESSION_KEY (symmetric key from encryption comms with NGC)
//    |<------|-------|             Get CHALLENGE from ngc
//    |-------|------>|                 return
//    .       .       |             Generate attestation report (with CHALLENGE & SESSION_KEY)
//    |<------|-------|             Send attestation report to ngc
//    |-------|------>|                 return
//    .       .       |             Finalize HELLO_KEY key (pop UI for user to enter PIN)
//    .       .       |             // Note: Now ngc will only send out encrypted data about HELLO_KEY
//    .       .       |
//    .       .       |         [STEP 2] Verify HELLO_KEY info
//    .       .       |             Construct requests to ngc to get info about the HELLO_KEY
//    |<------|-------|             Send requests to ngc to get info about the HELLO_KEY
//    |-------|------>|                 return
//    .       .       |             Decrypt ngc responses to get HELLO_KEY public bytes
//    .       .       |
//    .       .       |         [STEP 3] Diffie-Hellman
//    .       .       |             Generate  EPHEMERAL_KEY (ECDH key pair)
//    .       .       |             Derive    KEK (Key-Encryption-Key) from EPHEMERAL_KEY 'priv' and HELLO_KEY 'pub'
//    .       .       |             Discard   EPHEMERAL_KEY 'priv'
//    .       .       |             // Note: We can never re-materialize the KEK here, we will retrieve it via the
//    .       .       |             // the Hello trustlet/NGC in the future (during the 'Load Flow')
//    .       .       |
//    .       .       |         [STEP 4] Conceal user key
//    .       .       |             Encrypt   USER_KEY with KEK
//    .       .       |             Discard   KEK
//    .       .       |             
//    .       .       |             
//    .       |<------|
//    .       |       .             Save      EPHEMERAL_KEY 'pub' to disk
//    .       |       .             Save      USER_KEY (encrypted) to disk
//            v

namespace veil::vtl1::hello
{
    namespace implementation
    {
        struct encrypted_symmetric_key_information
        {
            uint8_t nonce[veil::vtl1::crypto::NONCE_SIZE];
            uint8_t tag[veil::vtl1::crypto::TAG_SIZE];
            uint8_t key[veil::vtl1::crypto::SYMMETRIC_KEY_SIZE_BYTES];

            // Implicit conversion operator to std::span
            operator std::span<uint8_t const>() const
            {
                return { reinterpret_cast<uint8_t const*>(this), sizeof(encrypted_symmetric_key_information) };
            }
        };

        struct hello_secured_key_material_variable_sized_version_1
        {
            constexpr static uint32_t STRUCT_VERSION = 1;

            uint32_t version = STRUCT_VERSION;
            uint32_t encryptedUserKeySize;
            uint32_t ephermeralPublicKeySize;
            uint32_t customDataSize;
            uint32_t helloKeyNameSize;
        };

        wil::secure_vector<uint8_t> serialize_hello_secured_key_material(std::span<uint8_t const> encryptedUserKeyInfo, std::span<uint8_t const> ephermeralPublicKey, std::span<uint8_t const> customData, std::wstring_view helloKeyName)
        {
            wil::secure_vector<uint8_t> keyMaterial(sizeof(hello_secured_key_material_variable_sized_version_1));
            auto keyContentStruct = reinterpret_cast<hello_secured_key_material_variable_sized_version_1*>(keyMaterial.data());
            keyContentStruct->version = 1;
            keyContentStruct->ephermeralPublicKeySize = gsl::narrow_cast<uint32_t>(ephermeralPublicKey.size());
            keyContentStruct->encryptedUserKeySize = gsl::narrow_cast<uint32_t>(encryptedUserKeyInfo.size());
            keyContentStruct->customDataSize = gsl::narrow_cast<uint32_t>(customData.size());
            keyContentStruct->helloKeyNameSize = gsl::narrow_cast<uint32_t>(helloKeyName.size() * sizeof(wchar_t));

            auto helloKeyNameData = veil::vtl1::as_data_span(helloKeyName);

            veil::any::add_buffer_bytes(keyMaterial, encryptedUserKeyInfo);
            veil::any::add_buffer_bytes(keyMaterial, ephermeralPublicKey);
            veil::any::add_buffer_bytes(keyMaterial, customData);
            veil::any::add_buffer_bytes(keyMaterial, helloKeyNameData);
            return keyMaterial;
        }

        std::tuple<
            std::span<const uint8_t>,
            std::span<const uint8_t>,
            std::span<const uint8_t>,
            std::wstring_view>
        deserialize_hello_secured_key_material(const std::span<const uint8_t>& keyMaterial)
        {
            auto bufferReader = veil::any::buffer_reader {keyMaterial};

            auto keyContent = bufferReader.read<hello_secured_key_material_variable_sized_version_1>();

            auto encryptedUserKey = bufferReader.read(keyContent->encryptedUserKeySize);
            auto ephemeralPubkeyPlaintext = bufferReader.read(keyContent->ephermeralPublicKeySize);
            auto customData = bufferReader.read(keyContent->customDataSize);
            auto bytes = bufferReader.read(keyContent->helloKeyNameSize);
            auto hello_key_name = std::wstring_view((wchar_t*)bytes.data(), bytes.size() / sizeof(wchar_t));

            THROW_HR_IF(E_INVALIDARG, keyContent->version != 1);

            return { encryptedUserKey, ephemeralPubkeyPlaintext, customData, hello_key_name};
        }
    }
}

namespace veil::vtl1::hello
{
    namespace implementation
    {
        namespace callouts
        {
            inline void close_handle_vtl1_ncrypt_key(NCRYPT_KEY_HANDLE keyHandle);
        }
    }

    using unique_vtl1_ncrypt_key = wil::unique_any<NCRYPT_KEY_HANDLE, decltype(&implementation::callouts::close_handle_vtl1_ncrypt_key), implementation::callouts::close_handle_vtl1_ncrypt_key>;

    namespace implementation
    {
        namespace callouts
        {
            inline void close_handle_vtl1_ncrypt_key(NCRYPT_KEY_HANDLE keyHandle)
            {
                // Call out to VTL0 to delete the backing threads (TODO:NOT SAFE UNTIL TOOLING WORK COMPLETE)
                void* output {};
                auto func = veil::vtl1::implementation::get_callback(veil::implementation::callback_id::hellokeys_close_handle_vtl1_ncrypt_key);
                THROW_IF_WIN32_BOOL_FALSE(::CallEnclave(func, reinterpret_cast<void*>(keyHandle), TRUE, reinterpret_cast<void**>(&output)));
                LOG_IF_FAILED(pvoid_to_hr(output));
            }

            [[nodiscard]] inline std::pair<unique_vtl1_ncrypt_key, bool> create_or_open_hello_key(std::wstring_view helloKeyName, std::wstring_view pinMessage, bool openOnly = false)
            {
                // Call out to VTL0 (TODO:NOT SAFE UNTIL TOOLING WORK COMPLETE)
                auto data = veil::vtl1::memory::allocate_vtl0<veil::any::implementation::args::hellokeys_create_or_open_hello_key>();
                data->openOnly = openOnly;

                {
                    auto cnt = veil::any::math_max(sizeof(data->helloKeyName), helloKeyName.size());
                    wcscpy_s(data->helloKeyName, cnt, helloKeyName.data());
                    data->helloKeyName[cnt] = L'\0';
                }
                {
                    auto cnt = veil::any::math_max(sizeof(data->pinMessage), pinMessage.size());
                    wcscpy_s(data->pinMessage, cnt, pinMessage.data());
                    data->pinMessage[cnt] = L'\0';
                }

                void* output {};
                auto func = veil::vtl1::implementation::get_callback(veil::implementation::callback_id::hellokeys_create_or_open_hello_key);
                THROW_IF_WIN32_BOOL_FALSE(::CallEnclave(func, reinterpret_cast<void*>(data.get()), TRUE, reinterpret_cast<void**>(&output)));
                THROW_IF_FAILED(pvoid_to_hr(output));

                return {unique_vtl1_ncrypt_key { data->helloKeyHandle }, data->createdKey};
            }

            [[nodiscard]] inline unique_vtl1_ncrypt_key open_hello_key(std::wstring_view helloKeyName)
            {
                return create_or_open_hello_key(helloKeyName, L"", true).first;
            }

            [[nodiscard]] inline std::vector<uint8_t> get_ngc_challenge(NCRYPT_KEY_HANDLE helloKeyHandle)
            {
                // Call out to VTL0 (TODO:NOT SAFE UNTIL TOOLING WORK COMPLETE)
                auto data = veil::vtl1::memory::allocate_vtl0<veil::any::implementation::args::hellokeys_get_challenge>();

                void* output {};
                auto func = veil::vtl1::implementation::get_callback(veil::implementation::callback_id::hellokeys_get_challenge);
                data->helloKeyHandle = helloKeyHandle;
                THROW_IF_WIN32_BOOL_FALSE(::CallEnclave(func, reinterpret_cast<void*>(data.get()), TRUE, reinterpret_cast<void**>(&output)));
                THROW_IF_FAILED(pvoid_to_hr(output));

                auto challenge = *data->challenge; // just visually being explicit about copy into vtl1... even though this isn't secure
                return challenge;
            }

            inline void send_attestation_report_to_ngc(NCRYPT_KEY_HANDLE helloKeyHandle, std::span<uint8_t const> report)
            {
                // Call out to VTL0 (TODO:NOT SAFE UNTIL TOOLING WORK COMPLETE)
                auto reportArray = veil::vtl1::memory::allocate_vtl0_array<uint8_t>(report.size());
                veil::vtl1::copy_span(report, reportArray);

                auto data = veil::vtl1::memory::allocate_vtl0<veil::any::implementation::args::hellokeys_send_attestation_report>();

                data->helloKeyHandle = helloKeyHandle;
                data->report = veil::vtl1::memory::as_data_blob(reportArray);

                void* output {};
                auto func = veil::vtl1::implementation::get_callback(veil::implementation::callback_id::hellokeys_send_attestation_report);
                THROW_IF_WIN32_BOOL_FALSE(::CallEnclave(func, reinterpret_cast<void*>(data.get()), TRUE, reinterpret_cast<void**>(&output)));
                THROW_IF_FAILED(pvoid_to_hr(output));
            }

            void hellokeys_finalize_key(NCRYPT_KEY_HANDLE helloKeyHandle, NCRYPT_NGC_CACHE_CONFIG cacheConfig, bool promptForUnlock)
            {
                // Call out to VTL0 (TODO:NOT SAFE UNTIL TOOLING WORK COMPLETE)
                auto data = veil::vtl1::memory::allocate_vtl0<veil::any::implementation::args::hellokeys_finalize_key>();
                data->helloKeyHandle = helloKeyHandle;
                data->cacheConfig = cacheConfig;
                data->promptForUnlock = promptForUnlock;

                void* output {};
                auto func = veil::vtl1::implementation::get_callback(veil::implementation::callback_id::hellokeys_finalize_key);
                THROW_IF_WIN32_BOOL_FALSE(::CallEnclave(func, reinterpret_cast<void*>(data.get()), TRUE, reinterpret_cast<void**>(&output)));
                THROW_IF_FAILED(pvoid_to_hr(output));
            }
        }

        struct ngc_session_challenge
        {
            const std::array<uint8_t, 10> header = {"challenge"};
            std::array<uint8_t, 24> challenge;
            PS_TRUSTLET_TKSESSION_ID sessionId;
        };

        inline std::tuple<decltype(ngc_session_challenge::challenge), PS_TRUSTLET_TKSESSION_ID> parse_ngc_session_challenge(std::span<uint8_t const> buffer)
        {
            THROW_HR_IF(NTE_BAD_DATA, buffer.size() != sizeof(ngc_session_challenge));
            auto bufferReader = veil::any::buffer_reader {buffer};
            auto _ignored_ = bufferReader.read<decltype(ngc_session_challenge::header)>(); // discard header
            auto challenge = bufferReader.read<decltype(ngc_session_challenge::challenge)>();
            auto sessionId = bufferReader.read<decltype(ngc_session_challenge::sessionId)>();
            (void)_ignored_; // explicitly using the variable to suppress warning
            return {*challenge, *sessionId};
        }

        [[nodiscard]] inline  std::vector<uint8_t> generate_attestation_report_for_ngc(std::vector<uint8_t> sessionChallenge, const veil::vtl1::crypto::symmetric_key_bytes& sessionKey)
        {
            auto [challengeBytes, sessionId] = parse_ngc_session_challenge(sessionChallenge);

            auto attestationBuffer = std::vector<uint8_t>();
            veil::any::add_buffer_bytes(attestationBuffer, std::array<uint8_t, 8>{"attest"});
            veil::any::add_buffer_bytes(attestationBuffer, challengeBytes);
            veil::any::add_buffer_bytes(attestationBuffer, sessionKey);

            std::array<uint8_t, ENCLAVE_REPORT_DATA_LENGTH> enclaveData {};
            veil::vtl1::copy_span(attestationBuffer, enclaveData);

            UINT32 reportSize {};
            THROW_IF_FAILED(::EnclaveGetAttestationReport(enclaveData.data(), nullptr, 0, &reportSize));

            std::vector<uint8_t> attestationReport(reportSize);
            THROW_IF_FAILED(::EnclaveGetAttestationReport(enclaveData.data(), attestationReport.data(), static_cast<uint32_t>(attestationReport.size()), &reportSize));

            TRUSTLET_BINDING_DATA trustletData {};
            #define TRUSTLETIDENTITY_NGC 6
            trustletData.TrustletIdentity = TRUSTLETIDENTITY_NGC;
            trustletData.TrustletSessionId = sessionId;
            trustletData.TrustletSvn = 0;
            trustletData.Reserved1 = 0;
            trustletData.Reserved2 = 0;

            UINT32 encryptedSize {};
            THROW_IF_FAILED(::EnclaveEncryptDataForTrustlet(attestationReport.data(), static_cast<uint32_t>(attestationReport.size()), &trustletData, nullptr, 0, &encryptedSize));

            std::vector<uint8_t> encryptedReport(encryptedSize);
            THROW_IF_FAILED(::EnclaveEncryptDataForTrustlet(
                attestationReport.data(),
                static_cast<uint32_t>(attestationReport.size()),
                &trustletData,
                encryptedReport.data(),
                static_cast<uint32_t>(encryptedReport.size()),
                &encryptedSize));

            return encryptedReport;
        }


        //
        // NGC requests
        //
        inline ULONG64 get_ngc_request_nonce()
        {
            constexpr ULONG64 c_maxRequestNonce = 100000; // arbitrary limit to prevent blatent key-loading abuse when requesting key information from NGC
            static ULONG64 s_requestNonce = 0;
            ULONG64 nonceNumber = InterlockedIncrement64(reinterpret_cast<LONG64*>(&s_requestNonce));
            THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_TOO_MANY_SECRETS), nonceNumber >= c_maxRequestNonce);
            return nonceNumber;
        }

        inline std::vector<uint8_t> encrypt_ngc_request(BCRYPT_KEY_HANDLE sessionKey, std::span<uint8_t const> plaintext, ULONG64 requestNonce)
        {
            auto nonceBuffer = veil::vtl1::crypto::make_nonce_buffer_from_number(requestNonce);
            auto tag = std::vector<uint8_t>(veil::vtl1::crypto::TAG_SIZE);
            auto cipherInfo = veil::vtl1::crypto::make_BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO(nonceBuffer, tag);
            auto output = veil::vtl1::crypto::encrypt(sessionKey, plaintext, &cipherInfo);

            auto nonceNumberAsSpan = std::span<uint8_t const> {reinterpret_cast<const uint8_t*>(&requestNonce), sizeof(requestNonce)};

            std::vector<uint8_t> ciphertext;
            ciphertext.insert(ciphertext.end(), nonceNumberAsSpan.begin(), nonceNumberAsSpan.end());
            ciphertext.insert(ciphertext.end(), output.begin(), output.end());
            ciphertext.insert(ciphertext.end(), tag.begin(), tag.end());

            return ciphertext;
        }

        inline wil::secure_vector<uint8_t> decrypt_ngc_response(BCRYPT_KEY_HANDLE sessionKey, std::span<uint8_t const> ciphertext, ULONG64 requestNonce)
        {
            THROW_HR_IF(NTE_BAD_DATA, ciphertext.size() < veil::vtl1::crypto::TAG_SIZE);

            constexpr ULONG64 c_responderBitFlip = 0x80000000;
            const ULONG64 expectedNonce = requestNonce ^ c_responderBitFlip;
            auto nonceBuffer = veil::vtl1::crypto::make_nonce_buffer_from_number(expectedNonce);
            return veil::vtl1::crypto::decrypt_and_untag(sessionKey, ciphertext, nonceBuffer);
        }

        template <typename T>
        inline T decrypt_ngc_response(BCRYPT_KEY_HANDLE sessionKey, std::span<uint8_t const> ciphertext, ULONG64 requestNonce)
        {
            auto decrypted = decrypt_ngc_response(sessionKey, ciphertext, requestNonce);
            THROW_HR_IF(E_INVALIDARG, decrypted.size() != sizeof(T));
            T value = *reinterpret_cast<T*>(decrypted.data());
            return value;
        }

        inline NgcReqResp::Request construct_ngc_request(NgcReqResp::Operation type, std::wstring_view helloKeyName, std::span<uint8_t const> publicKey = {})
        {
            NgcReqResp::Request request = {};
            request.op = type;
            request.keyName = helloKeyName;
            request.params = nullptr;
            if (type == NgcReqResp::Operation::DeriveSharedSecret)
            {
                auto params = std::make_unique<NgcReqResp::DeriveSharedSecretParams>();
                params->publicKey.insert(params->publicKey.end(), publicKey.begin(), publicKey.end());
                request.params = params.release();
            }
            return request;
        }

        inline std::vector<uint8_t> make_encrypted_ngc_request(BCRYPT_KEY_HANDLE sessionKey, std::wstring_view helloKeyName, ULONG64 nonce, NgcReqResp::Operation type, std::span<uint8_t const> publicKey = {})
        {
            NgcReqResp::Request request = implementation::construct_ngc_request(type, helloKeyName, publicKey);
            return encrypt_ngc_request(sessionKey, request.ToVector(), nonce);
        };
    }

    [[nodiscard]] inline std::pair<unique_vtl1_ncrypt_key, bool> create_or_open_hello_key(std::wstring_view helloKeyName, std::wstring_view pinMessage)
    {
        auto [helloKey, createdKey] = implementation::callouts::create_or_open_hello_key(helloKeyName, pinMessage);
        return { std::move(helloKey), createdKey };
    }

    [[nodiscard]] unique_vtl1_ncrypt_key open_hello_key(std::wstring_view helloKeyName)
    {
        return implementation::callouts::open_hello_key(helloKeyName);
    }

    [[nodiscard]] inline wil::secure_vector<uint8_t> conceal_encryption_key_with_hello(
        NCRYPT_KEY_HANDLE helloKey,
        const std::wstring& helloKeyName,
        NCRYPT_NGC_CACHE_CONFIG cacheConfig,
        std::span<uint8_t const> encryptionKeyToSecure,
        std::span<uint8_t const> customData,
        bool requireEnclaveOwnerIdMatchesHelloContainerSecureId = true)
    {
        // Generate a session key for talking to NGC (just for the duration of this our host process)
        auto sessionKeyBytes = veil::vtl1::crypto::generate_symmetric_key_bytes();
        auto sessionKey = veil::vtl1::crypto::create_symmetric_key(sessionKeyBytes);

        // STEP 1: Setup secure channel with NGC
        {
            // Get challenge from NGC
            auto challenge = implementation::callouts::get_ngc_challenge(helloKey);

            // Generate attestation report with session key and the NGC challenge
            auto attestationReport = implementation::generate_attestation_report_for_ngc(challenge, sessionKeyBytes);

            // Send attestation report to NGC
            implementation::callouts::send_attestation_report_to_ngc(helloKey, attestationReport);

            // Pop the UI for the user to enter Hello PIN
            implementation::callouts::hellokeys_finalize_key(helloKey, cacheConfig, true); // promptForUnlock

            // Milestone: Now the Hello key should be permanently configured to only send out encrypted information from NGC about the key
        }

        // STEP 2: Verify HELLO_KEY info
        
        // Now encrypt requests for NGC
        ULONG64 nonces[3] = {
            implementation::get_ngc_request_nonce(),
            implementation::get_ngc_request_nonce(),
            implementation::get_ngc_request_nonce(),
        };

        std::vector<uint8_t> buffers_vtl1[3];
        buffers_vtl1[0] = implementation::make_encrypted_ngc_request(sessionKey.get(), helloKeyName, nonces[0], NgcReqResp::Operation::GetIsSecureIdOwnerId);
        buffers_vtl1[1] = implementation::make_encrypted_ngc_request(sessionKey.get(), helloKeyName, nonces[1], NgcReqResp::Operation::GetCacheConfig);
        buffers_vtl1[2] = implementation::make_encrypted_ngc_request(sessionKey.get(), helloKeyName, nonces[2], NgcReqResp::Operation::ExportPublicKey);


        veil::vtl1::memory::unique_vtl0_array_ptr<uint8_t> buffers_vtl0[3]; // Remain on the stack for duration of callouts.
        buffers_vtl0[0] = veil::vtl1::memory::copy_to_vtl0_array(buffers_vtl1[0]);
        buffers_vtl0[1] = veil::vtl1::memory::copy_to_vtl0_array(buffers_vtl1[1]);
        buffers_vtl0[2] = veil::vtl1::memory::copy_to_vtl0_array(buffers_vtl1[2]);

        // Now send requests to NGC
        auto dataOut = veil::vtl1::memory::allocate_vtl0<veil::any::implementation::args::hellokeys_send_ngc_request>();
        dataOut->requests[0] = veil::vtl1::memory::as_data_blob(buffers_vtl0[0]);
        dataOut->requests[1] = veil::vtl1::memory::as_data_blob(buffers_vtl0[1]);
        dataOut->requests[2] = veil::vtl1::memory::as_data_blob(buffers_vtl0[2]);
        dataOut->helloKeyHandle = helloKey;
        dataOut->promptForUnlock = true;

        // Call out to VTL0 (TODO:NOT SAFE UNTIL TOOLING WORK COMPLETE)
        void* output {};
        auto func = veil::vtl1::implementation::get_callback(veil::implementation::callback_id::hellokeys_send_ngc_request);
        THROW_IF_WIN32_BOOL_FALSE(::CallEnclave(func, reinterpret_cast<void*>(dataOut.get()), TRUE, reinterpret_cast<void**>(&output)));
        THROW_IF_FAILED(pvoid_to_hr(output));

        // Now decrypt NGC's responses

        // Decrypt and verify the secure id is owner id state
        if (requireEnclaveOwnerIdMatchesHelloContainerSecureId)
        {
            auto isSecureIdOwnerId = implementation::decrypt_ngc_response<bool>(sessionKey.get(), dataOut->responses[0], nonces[0]);
            THROW_HR_IF(E_INVALIDARG, !isSecureIdOwnerId);
        }

        // Decrypt and verify key cache config
        auto actualCacheConfig = implementation::decrypt_ngc_response<NCRYPT_NGC_CACHE_CONFIG>(sessionKey.get(), dataOut->responses[1], nonces[1]);
        THROW_HR_IF(E_INVALIDARG, actualCacheConfig != STANDARD_HELLO_KEY_CACHE_CONFIG);

        // Decrypt they hello public key bytes
        auto helloPublicKeyBytes = implementation::decrypt_ngc_response(sessionKey.get(), dataOut->responses[2], nonces[2]);

        // Import the hello public key
        wil::unique_bcrypt_key helloPublicKeyHandle = veil::vtl1::crypto::bcrypt_import_key_pair(helloPublicKeyBytes);

        // STEP 3: Time for 'Elliptic-Curve Diffie-Hellman' (ECDH)

        wil::unique_bcrypt_key ephemeralKeyPair = veil::vtl1::crypto::bcrypt_generate_ecdh_key_pair();

        // Derive a key to use as a Key-Encryption-Key (KEK)
        wil::unique_bcrypt_key kek = veil::vtl1::crypto::bcrypt_derive_symmetric_key(ephemeralKeyPair.get(), helloPublicKeyHandle.get());

        // Export the ephemeral public key
        std::vector<uint8_t> ephemeralPublicKeyBytes = veil::vtl1::crypto::bcrypt_export_public_key(ephemeralKeyPair.get());

        // Note: We are discarding the ECHD private key! (explicit for clarity)
        // 
        //  This means we can never re-materialize the KEK here, we need Hello to do that for us
        //  using the Hello private key (and the ephemeral public key)
        ephemeralKeyPair.reset();

        // STEP 4: Conceal user's key

        // Encrypt the user's key with the KEK
        auto nonce = veil::vtl1::crypto::generate_random<sizeof(implementation::encrypted_symmetric_key_information::nonce)>();
        auto [key, tag] = veil::vtl1::crypto::encrypt(kek.get(), encryptionKeyToSecure, nonce);

        // Copy encrypted key data to a struct for serializing (i.e. for saving to disk)
        implementation::encrypted_symmetric_key_information encryptedKeyInfo;
        veil::vtl1::copy_span(nonce, encryptedKeyInfo.nonce);
        veil::vtl1::copy_span(key, encryptedKeyInfo.key);
        veil::vtl1::copy_span(tag, encryptedKeyInfo.tag);

        // Return 'serialized hello secured key material' bytes (that should be sealed by caller) and then returned to VTL0 to write to disk
        return implementation::serialize_hello_secured_key_material(encryptedKeyInfo, ephemeralPublicKeyBytes, customData, helloKeyName);
    }

    [[nodiscard]] inline wil::unique_bcrypt_key reveal_encryption_key_with_hello(std::span<uint8_t const> unsealedBytes, std::span<uint8_t const> expectedCustomData, bool requireEnclaveOwnerIdMatchesHelloContainerSecureId = true)
    {
        // Parse the secured key's material
        auto [encryptedUserKeyBytes, ephemeralPublicKeyBytes, customData, helloKeyName] = implementation::deserialize_hello_secured_key_material(unsealedBytes);

        // Load hello key that is the root of Hello-secured encryption key
        auto helloKey = veil::vtl1::hello::open_hello_key(helloKeyName);

        // Verify custom data matches
        if (!veil::vtl1::buffers_are_equal(customData, expectedCustomData))
        {
            THROW_WIN32(ERROR_INVALID_DATA);
        }

        // Generate a session key for talking to NGC (just for the duration of this our host process)
        auto sessionKeyBytes = veil::vtl1::crypto::generate_symmetric_key_bytes();
        auto sessionKey = veil::vtl1::crypto::create_symmetric_key(sessionKeyBytes);

        // STEP 1: Setup secure channel with NGC
        {
            // Get challenge from NGC
            auto challenge = implementation::callouts::get_ngc_challenge(helloKey.get());

            // Generate attestation report with session key and the NGC challenge
            auto attestationReport = implementation::generate_attestation_report_for_ngc(challenge, sessionKeyBytes);

            // Send attestation report to NGC
            implementation::callouts::send_attestation_report_to_ngc(helloKey.get(), attestationReport);
        }

        // STEP 2: Verify HELLO_KEY info

        // Now encrypt requests for NGC
        ULONG64 nonces[3] = {
            implementation::get_ngc_request_nonce(),
            implementation::get_ngc_request_nonce(),
            implementation::get_ngc_request_nonce(),
        };

        std::vector<uint8_t> buffers_vtl1[3];
        buffers_vtl1[0] = implementation::make_encrypted_ngc_request(sessionKey.get(), helloKeyName, nonces[0], NgcReqResp::Operation::GetIsSecureIdOwnerId);
        buffers_vtl1[1] = implementation::make_encrypted_ngc_request(sessionKey.get(), helloKeyName, nonces[1], NgcReqResp::Operation::GetCacheConfig);
        buffers_vtl1[2] = implementation::make_encrypted_ngc_request(sessionKey.get(), helloKeyName, nonces[2], NgcReqResp::Operation::DeriveSharedSecret, ephemeralPublicKeyBytes);

        veil::vtl1::memory::unique_vtl0_array_ptr<uint8_t> buffers_vtl0[3]; // Remain on the stack for duration of callouts.
        buffers_vtl0[0] = veil::vtl1::memory::copy_to_vtl0_array(buffers_vtl1[0]);
        buffers_vtl0[1] = veil::vtl1::memory::copy_to_vtl0_array(buffers_vtl1[1]);
        buffers_vtl0[2] = veil::vtl1::memory::copy_to_vtl0_array(buffers_vtl1[2]);

        // Now send requests to NGC
        auto dataOut = veil::vtl1::memory::allocate_vtl0<veil::any::implementation::args::hellokeys_send_ngc_request>();
        dataOut->requests[0] = veil::vtl1::memory::as_data_blob(buffers_vtl0[0]);
        dataOut->requests[1] = veil::vtl1::memory::as_data_blob(buffers_vtl0[1]);
        dataOut->requests[2] = veil::vtl1::memory::as_data_blob(buffers_vtl0[2]);  // THIS REQUEST WILL TRIGGER THE HELLO BIOMETRIC/PIN UI ENTRY
        dataOut->helloKeyHandle = helloKey.get();
        dataOut->promptForUnlock = true;

        // Call out to VTL0 (TODO:NOT SAFE UNTIL TOOLING WORK COMPLETE)
        void* output {};
        auto func = veil::vtl1::implementation::get_callback(veil::implementation::callback_id::hellokeys_send_ngc_request);
        THROW_IF_WIN32_BOOL_FALSE(::CallEnclave(func, reinterpret_cast<void*>(dataOut.get()), TRUE, reinterpret_cast<void**>(&output)));
        THROW_IF_FAILED(pvoid_to_hr(output));

        // Now decrypt NGC's responses

        // Decrypt and verify the secure id is owner id state
        if (requireEnclaveOwnerIdMatchesHelloContainerSecureId)
        {
            auto isSecureIdOwnerId = implementation::decrypt_ngc_response<bool>(sessionKey.get(), dataOut->responses[0], nonces[0]);
            THROW_HR_IF(E_INVALIDARG, !isSecureIdOwnerId);
        }

        // Decrypt and verify key cache config
        auto cacheConfig = implementation::decrypt_ngc_response<NCRYPT_NGC_CACHE_CONFIG>(sessionKey.get(), dataOut->responses[1], nonces[1]);
        THROW_HR_IF(E_INVALIDARG, cacheConfig != STANDARD_HELLO_KEY_CACHE_CONFIG);

        // STEP 3: Get KEK from Hello/NGC
        
        // Decrypt the KEK symmetric key bytes
        auto kekBytes = implementation::decrypt_ngc_response(sessionKey.get(), dataOut->responses[2], nonces[2]);

        // Get the KEK (the Hello-derived Key-Encryption-Key) that NGC re-materialized
        auto kek = veil::vtl1::crypto::create_symmetric_key(kekBytes);

        // STEP 4: Reveal user's key
        
        // Decrypt the user's encryption key
        auto encryptedUserKeyMaterial = reinterpret_cast<implementation::encrypted_symmetric_key_information const*>(encryptedUserKeyBytes.data());

        auto userKeyBytes = veil::vtl1::crypto::decrypt(kek.get(), encryptedUserKeyMaterial->key, encryptedUserKeyMaterial->nonce, encryptedUserKeyMaterial->tag);

        // Finally, return the unscrambled encryption key
        return veil::vtl1::crypto::create_symmetric_key(userKeyBytes);
    }
}
