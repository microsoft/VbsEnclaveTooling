// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "TlsMbedTlsDriver.h"

#include <algorithm>
#include <atomic>
#include <cstring>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/sha256.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <psa/crypto.h>

namespace tls_sample
{
    namespace
    {
        constexpr unsigned char Personalization[] = "vbs-enclave-tls-sample";

        // PSA crypto has process-global state, so it must be initialised once and
        // freed only when no session is using it. Reference-count init/free (guarded
        // by an enclave-compatible spinlock — no std::mutex in the enclave CRT) so
        // overlapping sessions cannot tear down PSA under one another.
        std::atomic_flag g_psaLock = ATOMIC_FLAG_INIT;
        int g_psaRefCount = 0;

        bool AcquirePsaCrypto()
        {
            while (g_psaLock.test_and_set(std::memory_order_acquire)) {}
            bool ok = true;
            if (g_psaRefCount == 0)
            {
                ok = (psa_crypto_init() == PSA_SUCCESS);
            }
            if (ok)
            {
                ++g_psaRefCount;
            }
            g_psaLock.clear(std::memory_order_release);
            return ok;
        }

        void ReleasePsaCrypto()
        {
            while (g_psaLock.test_and_set(std::memory_order_acquire)) {}
            if (g_psaRefCount > 0 && --g_psaRefCount == 0)
            {
                mbedtls_psa_crypto_free();
            }
            g_psaLock.clear(std::memory_order_release);
        }

        // Bound the work performed by a single Drive() call so control returns to
        // VTL0 regularly, and bound the whole session so a host that dribbles bytes
        // cannot keep the enclave busy indefinitely.
        constexpr int StepsPerDrive = 64;
        constexpr int MaxTotalSteps = 1'000'000;
        constexpr size_t RecvChunk = 16 * 1024;

        enum class State
        {
            Connecting,
            Handshaking,
            Writing,
            Reading,
            Done,
            Failed,
        };

        struct BioContext
        {
            TransportCallbacks callbacks{};
            uint64_t transportHandle{};
        };

        struct VerifyContext
        {
            std::array<uint8_t, 32> expectedCertificateSha256{};
            bool matched{};
        };

        int MbedTlsRecv(void* ctx, unsigned char* buffer, size_t length)
        {
            auto& context = *static_cast<BioContext*>(ctx);
            const auto ask = static_cast<uint32_t>((std::min)(length, RecvChunk));
            auto result = context.callbacks.recv(context.callbacks.context, context.transportHandle, ask);

            switch (result.status)
            {
            case HostIoStatus::Ok:
                break;
            case HostIoStatus::WouldBlock:
                return MBEDTLS_ERR_SSL_WANT_READ;
            case HostIoStatus::Closed:
                return 0;
            case HostIoStatus::Failed:
            default:
                return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
            }

            if (result.bytes.empty())
            {
                return MBEDTLS_ERR_SSL_WANT_READ;
            }

            // The enclave asked for at most `ask` bytes; a compliant host never
            // returns more. Reject a misbehaving host rather than overflow.
            if (result.bytes.size() > ask)
            {
                return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
            }

            const auto copied = (std::min)(length, result.bytes.size());
            std::memcpy(buffer, result.bytes.data(), copied);
            return static_cast<int>(copied);
        }

        int MbedTlsSend(void* ctx, const unsigned char* buffer, size_t length)
        {
            auto& context = *static_cast<BioContext*>(ctx);
            auto result = context.callbacks.send(context.callbacks.context, context.transportHandle, buffer, static_cast<uint32_t>(length));

            switch (result.status)
            {
            case HostIoStatus::Ok:
                return static_cast<int>((std::min)(static_cast<size_t>(result.bytesTransferred), length));
            case HostIoStatus::WouldBlock:
                return MBEDTLS_ERR_SSL_WANT_WRITE;
            case HostIoStatus::Closed:
            case HostIoStatus::Failed:
            default:
                return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
            }
        }

        // Callback-based pinning without a CA chain. Under VERIFY_OPTIONAL mbedTLS
        // does not fail the handshake on leftover flags, so this callback enforces
        // policy via its return value: it clears only the "untrusted issuer" flag
        // on a pin match (the sample deliberately trusts a pinned self-signed
        // leaf) and fails the handshake on a pin mismatch OR any other residual
        // flag such as a hostname/SAN mismatch.
        int VerifyPinnedCertificate(void* data, mbedtls_x509_crt* crt, int depth, uint32_t* flags)
        {
            auto& context = *static_cast<VerifyContext*>(data);
            if (depth != 0)
            {
                return 0;
            }

            std::array<uint8_t, 32> actual{};
            if (mbedtls_sha256(crt->raw.p, crt->raw.len, actual.data(), 0) != 0)
            {
                return MBEDTLS_ERR_X509_FATAL_ERROR;
            }

            if (actual != context.expectedCertificateSha256)
            {
                *flags |= MBEDTLS_X509_BADCERT_OTHER;
                return MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
            }

            context.matched = true;
            *flags &= ~static_cast<uint32_t>(MBEDTLS_X509_BADCERT_NOT_TRUSTED);
            if (*flags != 0)
            {
                // e.g. hostname/SAN mismatch: still reject.
                return MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
            }
            return 0;
        }

        // Manual substring search: the enclave CRT does not provide the
        // vectorized helpers that std::string::find pulls in.
        bool ExtractMultiplier(const std::string& response, uint32_t& multiplier)
        {
            static constexpr char marker[] = "\"multiplier\":";
            constexpr size_t markerLen = sizeof(marker) - 1;
            if (response.size() < markerLen)
            {
                return false;
            }

            size_t marker_pos = std::string::npos;
            for (size_t i = 0; i + markerLen <= response.size(); ++i)
            {
                if (std::memcmp(response.data() + i, marker, markerLen) == 0)
                {
                    marker_pos = i;
                    break;
                }
            }
            if (marker_pos == std::string::npos)
            {
                return false;
            }

            size_t i = marker_pos + markerLen;
            while (i < response.size() && (response[i] == ' ' || response[i] == '\t'))
            {
                ++i;
            }

            uint32_t value = 0;
            const size_t start = i;
            for (; i < response.size() && response[i] >= '0' && response[i] <= '9'; ++i)
            {
                const uint32_t digit = static_cast<uint32_t>(response[i] - '0');
                if (value > (UINT32_MAX - digit) / 10)
                {
                    return false;  // reject rather than silently wrap
                }
                value = (value * 10) + digit;
            }

            if (i == start)
            {
                return false;
            }
            multiplier = value;
            return true;
        }
    }

    struct TlsSession::Impl
    {
        ScenarioPolicy policy;
        uint32_t inputValue{};
        TransportCallbacks callbacks;

        State state{State::Connecting};
        bool transportOpen{};
        bool cryptoReady{};
        uint64_t transportHandle{};
        int totalSteps{};

        BioContext bio{};
        VerifyContext verify{};

        mbedtls_ssl_context ssl{};
        mbedtls_ssl_config config{};
        mbedtls_ctr_drbg_context ctrDrbg{};
        mbedtls_entropy_context entropy{};

        std::string request;
        size_t writeOffset{};
        std::string response;

        TlsResult result{};

        Impl(const ScenarioPolicy& scenarioPolicy, uint32_t input, const TransportCallbacks& transport) :
            policy(scenarioPolicy), inputValue(input), callbacks(transport)
        {
            mbedtls_ssl_init(&ssl);
            mbedtls_ssl_config_init(&config);
            mbedtls_ctr_drbg_init(&ctrDrbg);
            mbedtls_entropy_init(&entropy);
            verify.expectedCertificateSha256 = policy.pinnedCertificateSha256;
        }

        ~Impl()
        {
            if (transportOpen)
            {
                (void)callbacks.close(callbacks.context, transportHandle);
            }
            mbedtls_entropy_free(&entropy);
            mbedtls_ctr_drbg_free(&ctrDrbg);
            mbedtls_ssl_config_free(&config);
            mbedtls_ssl_free(&ssl);
            if (cryptoReady)
            {
                ReleasePsaCrypto();
            }
        }

        TlsSampleProgress Fail(TlsSampleStatus reason)
        {
            state = State::Failed;
            result.status = reason;
            result.failureReason = reason;
            return TlsSampleProgress::Failed;
        }

        bool Setup()
        {
            request = "GET " + policy.httpPath + " HTTP/1.1\r\nHost: " + policy.tlsServerName + "\r\nConnection: close\r\n\r\n";

            if (!AcquirePsaCrypto())
            {
                return false;
            }
            cryptoReady = true;

            if (mbedtls_ctr_drbg_seed(&ctrDrbg, mbedtls_entropy_func, &entropy, Personalization, sizeof(Personalization) - 1) != 0)
            {
                return false;
            }
            if (mbedtls_ssl_config_defaults(&config, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) != 0)
            {
                return false;
            }

            mbedtls_ssl_conf_min_tls_version(&config, MBEDTLS_SSL_VERSION_TLS1_3);
            mbedtls_ssl_conf_max_tls_version(&config, MBEDTLS_SSL_VERSION_TLS1_3);
            mbedtls_ssl_conf_rng(&config, mbedtls_ctr_drbg_random, &ctrDrbg);
            // VERIFY_OPTIONAL: no CA chain is configured (the sample pins the leaf
            // certificate instead), so the verify callback enforces trust by
            // returning failure rather than relying on mbedTLS's flag check.
            mbedtls_ssl_conf_authmode(&config, MBEDTLS_SSL_VERIFY_OPTIONAL);
            mbedtls_ssl_conf_verify(&config, VerifyPinnedCertificate, &verify);

            if (mbedtls_ssl_setup(&ssl, &config) != 0)
            {
                return false;
            }
            if (mbedtls_ssl_set_hostname(&ssl, policy.tlsServerName.c_str()) != 0)
            {
                return false;
            }
            bio.callbacks = callbacks;
            bio.transportHandle = transportHandle;
            mbedtls_ssl_set_bio(&ssl, &bio, MbedTlsSend, MbedTlsRecv, nullptr);
            return true;
        }

        void RecordProtocolFacts()
        {
            result.tlsVersion = static_cast<uint32_t>(mbedtls_ssl_get_version_number(&ssl));
            result.cipherSuite = static_cast<uint16_t>(mbedtls_ssl_get_ciphersuite_id_from_ssl(&ssl));
        }

        TlsSampleProgress Drive()
        {
            // A terminal session does no further work: return its settled result
            // without consuming budget (so repeated polling of a Failed/Done
            // session cannot overwrite its real failureReason with BudgetExceeded).
            if (state == State::Done)
            {
                return TlsSampleProgress::Completed;
            }
            if (state == State::Failed)
            {
                return TlsSampleProgress::Failed;
            }

            for (int step = 0; step < StepsPerDrive; ++step)
            {
                if (++totalSteps > MaxTotalSteps)
                {
                    return Fail(TlsSampleStatus::BudgetExceeded);
                }

                switch (state)
                {
                case State::Connecting:
                {
                    if (!callbacks.connect || !callbacks.recv || !callbacks.send || !callbacks.close)
                    {
                        return Fail(TlsSampleStatus::TransportFailed);
                    }
                    auto connectResult = callbacks.connect(callbacks.context, policy.connectHost, policy.connectPort);
                    if (connectResult.status != HostIoStatus::Ok)
                    {
                        return Fail(TlsSampleStatus::TransportFailed);
                    }
                    transportHandle = connectResult.transportHandle;
                    transportOpen = true;
                    if (!Setup())
                    {
                        return Fail(TlsSampleStatus::ProtocolFailed);
                    }
                    state = State::Handshaking;
                    break;
                }

                case State::Handshaking:
                {
                    const int rc = mbedtls_ssl_handshake(&ssl);
                    if (rc == 0)
                    {
                        if (!verify.matched)
                        {
                            return Fail(TlsSampleStatus::ValidationFailed);
                        }
                        state = State::Writing;
                        break;
                    }
                    if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE)
                    {
                        return TlsSampleProgress::WouldBlock;
                    }
                    // A pin/hostname rejection from our verify callback surfaces as
                    // CERT_VERIFY_FAILED or, when the callback returns non-zero, as
                    // X509_FATAL_ERROR. Both mean the server was not authenticated.
                    if (rc == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED || rc == MBEDTLS_ERR_X509_FATAL_ERROR)
                    {
                        return Fail(TlsSampleStatus::ValidationFailed);
                    }
                    return Fail(TlsSampleStatus::ProtocolFailed);
                }

                case State::Writing:
                {
                    const auto* data = reinterpret_cast<const unsigned char*>(request.data());
                    const int rc = mbedtls_ssl_write(&ssl, data + writeOffset, request.size() - writeOffset);
                    if (rc > 0)
                    {
                        writeOffset += static_cast<size_t>(rc);
                        if (writeOffset >= request.size())
                        {
                            state = State::Reading;
                        }
                        break;
                    }
                    if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE)
                    {
                        return TlsSampleProgress::WouldBlock;
                    }
                    return Fail(TlsSampleStatus::ProtocolFailed);
                }

                case State::Reading:
                {
                    std::array<unsigned char, 2048> buffer{};
                    const int rc = mbedtls_ssl_read(&ssl, buffer.data(), buffer.size());
                    if (rc > 0)
                    {
                        if (response.size() + static_cast<size_t>(rc) > policy.maxResponseBytes)
                        {
                            return Fail(TlsSampleStatus::Truncated);
                        }
                        response.append(reinterpret_cast<const char*>(buffer.data()), static_cast<size_t>(rc));
                        break;
                    }
                    if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE)
                    {
                        return TlsSampleProgress::WouldBlock;
                    }
                    if (rc == 0 || rc == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
                    {
                        return Finish();
                    }
                    return Fail(TlsSampleStatus::ProtocolFailed);
                }

                case State::Done:
                    return TlsSampleProgress::Completed;
                case State::Failed:
                    return TlsSampleProgress::Failed;
                }
            }

            return TlsSampleProgress::Working;
        }

        TlsSampleProgress Finish()
        {
            uint32_t multiplier{};
            if (!ExtractMultiplier(response, multiplier))
            {
                return Fail(TlsSampleStatus::ProtocolFailed);
            }

            result.outputValue = inputValue * multiplier;
            result.decision = (inputValue % 2 == 0) ? TlsSampleDecision::Allow : TlsSampleDecision::Deny;
            result.status = TlsSampleStatus::Ok;
            result.failureReason = TlsSampleStatus::Ok;
            RecordProtocolFacts();
            state = State::Done;
            return TlsSampleProgress::Completed;
        }
    };

    TlsSession::TlsSession(const ScenarioPolicy& policy, uint32_t inputValue, const TransportCallbacks& callbacks) :
        m_impl(std::make_unique<Impl>(policy, inputValue, callbacks))
    {
    }

    TlsSession::~TlsSession() = default;

    TlsSampleProgress TlsSession::Drive()
    {
        return m_impl->Drive();
    }

    const TlsResult& TlsSession::Result() const noexcept
    {
        return m_impl->result;
    }

    std::array<uint8_t, 32> ComputeCertificateSha256(std::vector<uint8_t> const& certificatePem)
    {
        mbedtls_x509_crt certificate;
        mbedtls_x509_crt_init(&certificate);
        std::array<uint8_t, 32> digest{};
        auto parseBuffer = certificatePem;
        parseBuffer.push_back(0);

        if (mbedtls_x509_crt_parse(&certificate, parseBuffer.data(), parseBuffer.size()) == 0)
        {
            (void)mbedtls_sha256(certificate.raw.p, certificate.raw.len, digest.data(), 0);
        }
        mbedtls_x509_crt_free(&certificate);
        return digest;
    }

    bool IsEmptySha256(std::array<uint8_t, 32> const& digest)
    {
        return std::all_of(digest.begin(), digest.end(), [](uint8_t value) { return value == 0; });
    }
}
