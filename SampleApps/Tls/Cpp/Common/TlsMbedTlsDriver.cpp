// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "TlsMbedTlsDriver.h"

#include <algorithm>
#include <charconv>
#include <cstring>
#include <sstream>

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
        constexpr int MaxHandshakeSteps = 10000;

        struct BioContext
        {
            TransportCallbacks callbacks;
            uint64_t transportHandle{};
            std::vector<uint8_t> pendingRead;
        };

        struct VerifyContext
        {
            std::array<uint8_t, 32> expectedCertificateSha256;
            bool matched{};
        };

        int ToMbedTlsRecvResult(HostTcpRecvResult& result, unsigned char* buffer, size_t length, BioContext& context)
        {
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

            const auto copied = (std::min)(length, result.bytes.size());
            std::memcpy(buffer, result.bytes.data(), copied);
            if (copied < result.bytes.size())
            {
                context.pendingRead.assign(result.bytes.begin() + copied, result.bytes.end());
            }
            return static_cast<int>(copied);
        }

        int MbedTlsRecv(void* ctx, unsigned char* buffer, size_t length)
        {
            auto& context = *static_cast<BioContext*>(ctx);
            if (!context.pendingRead.empty())
            {
                const auto copied = (std::min)(length, context.pendingRead.size());
                std::memcpy(buffer, context.pendingRead.data(), copied);
                context.pendingRead.erase(context.pendingRead.begin(), context.pendingRead.begin() + copied);
                return static_cast<int>(copied);
            }

            auto result = context.callbacks.recv(
                context.callbacks.context,
                context.transportHandle,
                static_cast<uint32_t>((std::min)(length, static_cast<size_t>(16 * 1024))));
            return ToMbedTlsRecvResult(result, buffer, length, context);
        }

        int MbedTlsSend(void* ctx, const unsigned char* buffer, size_t length)
        {
            auto& context = *static_cast<BioContext*>(ctx);
            auto result = context.callbacks.send(
                context.callbacks.context,
                context.transportHandle,
                buffer,
                static_cast<uint32_t>(length));

            switch (result.status)
            {
            case HostIoStatus::Ok:
                return static_cast<int>(result.bytesTransferred);
            case HostIoStatus::WouldBlock:
                return MBEDTLS_ERR_SSL_WANT_WRITE;
            case HostIoStatus::Closed:
            case HostIoStatus::Failed:
            default:
                return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
            }
        }

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
            *flags = 0;
            return 0;
        }

        std::string MakeRequest(const TlsRequest& request)
        {
            std::ostringstream builder;
            builder << "GET " << request.httpPath << " HTTP/1.1\r\n"
                    << "Host: " << request.serverName << "\r\n"
                    << "Connection: close\r\n\r\n";
            return builder.str();
        }

        bool ExtractMultiplier(const std::string& response, uint32_t& multiplier)
        {
            const std::string marker = "\"multiplier\":";
            const auto markerOffset = response.find(marker);
            if (markerOffset == std::string::npos)
            {
                return false;
            }

            const char* begin = response.data() + markerOffset + marker.size();
            const char* end = response.data() + response.size();
            while (begin != end && (*begin == ' ' || *begin == '\t'))
            {
                ++begin;
            }

            auto [ptr, ec] = std::from_chars(begin, end, multiplier);
            return ec == std::errc{} && ptr != begin;
        }

        TlsSampleStatus MapHandshakeError(int error)
        {
            if (error == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED)
            {
                return TlsSampleStatus::ValidationFailed;
            }
            return TlsSampleStatus::ProtocolFailed;
        }

        std::string MbedTlsError(int error)
        {
            std::array<char, 256> buffer{};
            mbedtls_strerror(error, buffer.data(), buffer.size());
            std::ostringstream message;
            message << "mbedTLS error " << error << ": " << buffer.data();
            return message.str();
        }

        void SetProtocolDiagnostics(TlsResult& result, mbedtls_ssl_context& ssl)
        {
            result.tlsVersion = static_cast<uint32_t>(mbedtls_ssl_get_version_number(&ssl));
            result.cipherSuite = static_cast<uint16_t>(mbedtls_ssl_get_ciphersuite_id_from_ssl(&ssl));

            std::ostringstream diagnostics;
            diagnostics << mbedtls_ssl_get_version(&ssl) << ", " << mbedtls_ssl_get_ciphersuite(&ssl) << ", server-auth-ok";
            result.diagnostics = diagnostics.str();
        }
    }

    std::array<uint8_t, 32> ComputeCertificateSha256(std::vector<uint8_t> const& certificatePem)
    {
        mbedtls_x509_crt certificate;
        mbedtls_x509_crt_init(&certificate);
        std::array<uint8_t, 32> digest{};
        auto parseBuffer = certificatePem;
        parseBuffer.push_back(0);

        if (mbedtls_x509_crt_parse(&certificate, parseBuffer.data(), parseBuffer.size()) != 0)
        {
            mbedtls_x509_crt_free(&certificate);
            return digest;
        }

        (void)mbedtls_sha256(certificate.raw.p, certificate.raw.len, digest.data(), 0);
        mbedtls_x509_crt_free(&certificate);
        return digest;
    }

    bool IsEmptySha256(std::array<uint8_t, 32> const& digest)
    {
        return std::all_of(digest.begin(), digest.end(), [](uint8_t value) { return value == 0; });
    }

    TlsResult RunServerAuthScenario(const TlsRequest& request, const TransportCallbacks& callbacks)
    {
        TlsResult result;
        if (!callbacks.connect || !callbacks.recv || !callbacks.send || !callbacks.close)
        {
            result.status = TlsSampleStatus::TransportFailed;
            return result;
        }

        auto connectResult = callbacks.connect(callbacks.context, request.serverName, request.serverPort);
        if (connectResult.status != HostIoStatus::Ok)
        {
            result.status = TlsSampleStatus::TransportFailed;
            return result;
        }

        BioContext bio{callbacks, connectResult.transportHandle};
        VerifyContext verify{request.pinnedServerCertificateSha256};

        mbedtls_ssl_context ssl;
        mbedtls_ssl_config config;
        mbedtls_ctr_drbg_context ctrDrbg;
        mbedtls_entropy_context entropy;

        mbedtls_ssl_init(&ssl);
        mbedtls_ssl_config_init(&config);
        mbedtls_ctr_drbg_init(&ctrDrbg);
        mbedtls_entropy_init(&entropy);

        auto cleanup = [&]() {
            (void)callbacks.close(callbacks.context, connectResult.transportHandle);
            mbedtls_entropy_free(&entropy);
            mbedtls_ctr_drbg_free(&ctrDrbg);
            mbedtls_ssl_config_free(&config);
            mbedtls_ssl_free(&ssl);
            mbedtls_psa_crypto_free();
        };

        if (psa_crypto_init() != PSA_SUCCESS)
        {
            cleanup();
            result.status = TlsSampleStatus::ProtocolFailed;
            result.diagnostics = "psa_crypto_init failed";
            return result;
        }

        const int seedResult = mbedtls_ctr_drbg_seed(&ctrDrbg, mbedtls_entropy_func, &entropy, Personalization, sizeof(Personalization) - 1);
        if (seedResult != 0)
        {
            cleanup();
            result.status = TlsSampleStatus::ProtocolFailed;
            result.diagnostics = MbedTlsError(seedResult);
            return result;
        }

        const int configResult = mbedtls_ssl_config_defaults(&config, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
        if (configResult != 0)
        {
            cleanup();
            result.status = TlsSampleStatus::ProtocolFailed;
            result.diagnostics = MbedTlsError(configResult);
            return result;
        }

        mbedtls_ssl_conf_min_tls_version(&config, MBEDTLS_SSL_VERSION_TLS1_3);
        mbedtls_ssl_conf_max_tls_version(&config, MBEDTLS_SSL_VERSION_TLS1_3);
        mbedtls_ssl_conf_rng(&config, mbedtls_ctr_drbg_random, &ctrDrbg);
        mbedtls_ssl_conf_authmode(&config, MBEDTLS_SSL_VERIFY_OPTIONAL);
        mbedtls_ssl_conf_verify(&config, VerifyPinnedCertificate, &verify);

        const int setupResult = mbedtls_ssl_setup(&ssl, &config);
        if (setupResult != 0)
        {
            cleanup();
            result.status = TlsSampleStatus::ProtocolFailed;
            result.diagnostics = MbedTlsError(setupResult);
            return result;
        }

        const int hostnameResult = mbedtls_ssl_set_hostname(&ssl, request.serverName.c_str());
        if (hostnameResult != 0)
        {
            cleanup();
            result.status = TlsSampleStatus::ProtocolFailed;
            result.diagnostics = MbedTlsError(hostnameResult);
            return result;
        }

        mbedtls_ssl_set_bio(&ssl, &bio, MbedTlsSend, MbedTlsRecv, nullptr);

        int handshakeResult = 0;
        for (int i = 0; i < MaxHandshakeSteps; ++i)
        {
            handshakeResult = mbedtls_ssl_handshake(&ssl);
            if (handshakeResult == 0)
            {
                break;
            }
            if (handshakeResult != MBEDTLS_ERR_SSL_WANT_READ && handshakeResult != MBEDTLS_ERR_SSL_WANT_WRITE)
            {
                cleanup();
                result.status = MapHandshakeError(handshakeResult);
                result.diagnostics = MbedTlsError(handshakeResult);
                return result;
            }
        }

        if (handshakeResult != 0 || !verify.matched)
        {
            cleanup();
            result.status = TlsSampleStatus::ValidationFailed;
            result.diagnostics = handshakeResult == 0 ? "server certificate pin mismatch" : MbedTlsError(handshakeResult);
            return result;
        }

        const auto httpRequest = MakeRequest(request);
        int writeResult = mbedtls_ssl_write(&ssl, reinterpret_cast<const unsigned char*>(httpRequest.data()), httpRequest.size());
        if (writeResult < 0)
        {
            cleanup();
            result.status = TlsSampleStatus::ProtocolFailed;
            return result;
        }

        std::string response;
        std::array<unsigned char, 1024> buffer{};
        while (response.size() < request.maxResponseBytes)
        {
            const int read = mbedtls_ssl_read(&ssl, buffer.data(), buffer.size());
            if (read > 0)
            {
                response.append(reinterpret_cast<const char*>(buffer.data()), static_cast<size_t>(read));
                continue;
            }
            if (read == 0 || read == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
            {
                break;
            }
            if (read == MBEDTLS_ERR_SSL_WANT_READ || read == MBEDTLS_ERR_SSL_WANT_WRITE)
            {
                continue;
            }

            cleanup();
            result.status = TlsSampleStatus::Truncated;
            return result;
        }

        uint32_t multiplier{};
        if (!ExtractMultiplier(response, multiplier))
        {
            cleanup();
            result.status = TlsSampleStatus::ProtocolFailed;
            return result;
        }

        result.outputValue = request.inputValue * multiplier;
        result.decision = (request.inputValue % 2 == 0) ? "Allow" : "Deny";
        result.status = TlsSampleStatus::Ok;
        SetProtocolDiagnostics(result, ssl);

        cleanup();
        return result;
    }
}
