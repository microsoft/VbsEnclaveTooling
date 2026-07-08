// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace tls_sample
{
    enum class HostIoStatus : uint32_t
    {
        Ok = 0,
        WouldBlock = 1,
        Closed = 2,
        Failed = 3,
    };

    // Mirrors TlsSampleStatus in TlsTransport.edl.
    enum class TlsSampleStatus : uint32_t
    {
        Ok = 0,
        Closed = 1,
        Truncated = 2,
        ValidationFailed = 3,
        TransportFailed = 4,
        ProtocolFailed = 5,
        AccessDenied = 6,
        BudgetExceeded = 7,
        InvalidHandle = 8,
        InvalidState = 9,
        UnknownScenario = 10,
    };

    // Result of one bounded Drive() step, mirrors TlsSampleProgress in the EDL.
    enum class TlsSampleProgress : uint32_t
    {
        Working = 0,
        WouldBlock = 1,
        Completed = 2,
        Failed = 3,
    };

    enum class TlsSampleDecision : uint32_t
    {
        Deny = 0,
        Allow = 1,
    };

    struct HostTcpConnectResult
    {
        HostIoStatus status{};
        uint64_t transportHandle{};
        uint32_t hostError{};
    };

    struct HostTcpRecvResult
    {
        HostIoStatus status{};
        std::vector<uint8_t> bytes;
        uint32_t hostError{};
    };

    struct HostIoResult
    {
        HostIoStatus status{};
        uint32_t bytesTransferred{};
        uint32_t hostError{};
    };

    struct TransportCallbacks
    {
        void* context{};
        HostTcpConnectResult (*connect)(void* context, const std::string& serverName, uint16_t serverPort) {};
        HostTcpRecvResult (*recv)(void* context, uint64_t transportHandle, uint32_t maxBytes) {};
        HostIoResult (*send)(void* context, uint64_t transportHandle, const uint8_t* bytes, uint32_t byteCount) {};
        HostIoResult (*close)(void* context, uint64_t transportHandle) {};
    };

    // Enclave-owned, immutable policy for a scenario. VTL0 never supplies any of
    // this; it only names a scenario by id. pinnedCertificateSha256 is the
    // SHA-256 of the server's leaf certificate (DER), fixed at enclave build time.
    struct ScenarioPolicy
    {
        uint32_t scenarioId{};
        std::string connectHost;                            // where VTL0 is told to connect
        uint16_t connectPort{};
        std::string tlsServerName;                          // SNI / hostname the enclave validates
        std::string httpPath;                               // enclave-owned request target
        uint32_t maxResponseBytes{16 * 1024};               // enclave-owned response cap
        std::array<uint8_t, 32> pinnedCertificateSha256{};  // enclave-owned trust anchor
    };

    // Derived, bounded, non-secret result. failureReason is deliberately coarse
    // so it cannot become an oracle for decrypted server content.
    struct TlsResult
    {
        TlsSampleStatus status{TlsSampleStatus::InvalidState};
        TlsSampleDecision decision{TlsSampleDecision::Deny};
        uint32_t outputValue{};
        uint32_t tlsVersion{};
        uint16_t cipherSuite{};
        TlsSampleStatus failureReason{TlsSampleStatus::Ok};
    };

    // A resumable server-auth TLS client session. Each Drive() performs a bounded
    // amount of work and hands control back to the caller (VTL0), so a hostile or
    // slow host cannot trap the enclave in an unbounded loop. All mbedTLS state is
    // owned by the session and released in its destructor (RAII).
    class TlsSession
    {
    public:
        TlsSession(const ScenarioPolicy& policy, uint32_t inputValue, const TransportCallbacks& callbacks);
        ~TlsSession();

        TlsSession(const TlsSession&) = delete;
        TlsSession& operator=(const TlsSession&) = delete;

        // Advances the session by up to one bounded budget of work.
        TlsSampleProgress Drive();

        const TlsResult& Result() const noexcept;

    private:
        struct Impl;
        std::unique_ptr<Impl> m_impl;
    };

    // Utility used by the host tools (and tests) to compute a leaf-certificate pin.
    std::array<uint8_t, 32> ComputeCertificateSha256(std::vector<uint8_t> const& certificatePem);
    bool IsEmptySha256(std::array<uint8_t, 32> const& digest);
}
