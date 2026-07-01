// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <array>
#include <cstdint>
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

    enum class TlsSampleStatus : uint32_t
    {
        Ok = 0,
        WouldBlock = 1,
        Closed = 2,
        Truncated = 3,
        ValidationFailed = 4,
        TransportFailed = 5,
        ProtocolFailed = 6,
        AccessDenied = 7,
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

    struct TlsRequest
    {
        std::string serverName;
        uint16_t serverPort{};
        std::string httpPath;
        uint32_t inputValue{};
        uint32_t maxResponseBytes{16 * 1024};
        std::array<uint8_t, 32> pinnedServerCertificateSha256{};
    };

    struct TlsResult
    {
        TlsSampleStatus status{TlsSampleStatus::ProtocolFailed};
        uint32_t outputValue{};
        std::string decision;
        std::string diagnostics;
        uint32_t tlsVersion{};
        uint16_t cipherSuite{};
    };

    TlsResult RunServerAuthScenario(const TlsRequest& request, const TransportCallbacks& callbacks);
    std::array<uint8_t, 32> ComputeCertificateSha256(std::vector<uint8_t> const& certificatePem);
    bool IsEmptySha256(std::array<uint8_t, 32> const& digest);
}
