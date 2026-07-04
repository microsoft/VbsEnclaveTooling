// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "TlsMbedTlsDriver.h"

#include <algorithm>

#include <VbsEnclave\Enclave\Abi\Exports.TlsTransport.cpp>
#include <VbsEnclave\Enclave\Implementation\Trusted.h>
#include <VbsEnclave\Enclave\Stubs\Untrusted.h>

namespace
{
    tls_sample::HostIoStatus MapHostStatus(TlsSample::Types::HostIoStatus status)
    {
        switch (status)
        {
        case TlsSample::Types::HostIoStatus::HostIoStatus_Ok:
            return tls_sample::HostIoStatus::Ok;
        case TlsSample::Types::HostIoStatus::HostIoStatus_WouldBlock:
            return tls_sample::HostIoStatus::WouldBlock;
        case TlsSample::Types::HostIoStatus::HostIoStatus_Closed:
            return tls_sample::HostIoStatus::Closed;
        case TlsSample::Types::HostIoStatus::HostIoStatus_Failed:
        default:
            return tls_sample::HostIoStatus::Failed;
        }
    }

    TlsSample::Types::TlsSampleStatus MapTlsStatus(tls_sample::TlsSampleStatus status)
    {
        switch (status)
        {
        case tls_sample::TlsSampleStatus::Ok:
            return TlsSample::Types::TlsSampleStatus::TlsSampleStatus_Ok;
        case tls_sample::TlsSampleStatus::WouldBlock:
            return TlsSample::Types::TlsSampleStatus::TlsSampleStatus_WouldBlock;
        case tls_sample::TlsSampleStatus::Closed:
            return TlsSample::Types::TlsSampleStatus::TlsSampleStatus_Closed;
        case tls_sample::TlsSampleStatus::Truncated:
            return TlsSample::Types::TlsSampleStatus::TlsSampleStatus_Truncated;
        case tls_sample::TlsSampleStatus::ValidationFailed:
            return TlsSample::Types::TlsSampleStatus::TlsSampleStatus_ValidationFailed;
        case tls_sample::TlsSampleStatus::TransportFailed:
            return TlsSample::Types::TlsSampleStatus::TlsSampleStatus_TransportFailed;
        case tls_sample::TlsSampleStatus::AccessDenied:
            return TlsSample::Types::TlsSampleStatus::TlsSampleStatus_AccessDenied;
        case tls_sample::TlsSampleStatus::ProtocolFailed:
        default:
            return TlsSample::Types::TlsSampleStatus::TlsSampleStatus_ProtocolFailed;
        }
    }

    tls_sample::HostTcpConnectResult Connect(void*, const std::string& serverName, uint16_t serverPort)
    {
        const auto result = TlsSample::Untrusted::Stubs::TlsSample_HostTcpConnect(serverName, serverPort);
        return {MapHostStatus(result.status), result.transport_handle, result.host_error};
    }

    tls_sample::HostTcpRecvResult Recv(void*, uint64_t transportHandle, uint32_t maxBytes)
    {
        const auto result = TlsSample::Untrusted::Stubs::TlsSample_HostTcpRecv(transportHandle, maxBytes);
        return {MapHostStatus(result.status), result.bytes, result.host_error};
    }

    tls_sample::HostIoResult Send(void*, uint64_t transportHandle, const uint8_t* bytes, uint32_t byteCount)
    {
        const std::vector<uint8_t> payload(bytes, bytes + byteCount);
        const auto result = TlsSample::Untrusted::Stubs::TlsSample_HostTcpSend(transportHandle, payload);
        return {MapHostStatus(result.status), result.bytes_transferred, result.host_error};
    }

    tls_sample::HostIoResult Close(void*, uint64_t transportHandle)
    {
        const auto result = TlsSample::Untrusted::Stubs::TlsSample_HostTcpClose(transportHandle);
        return {MapHostStatus(result.status), result.bytes_transferred, result.host_error};
    }
}

HRESULT TlsSample::Trusted::Implementation::TlsSample_RunScenario(
    _In_ const TlsSampleRequest& request,
    _Out_ TlsSampleResult& result)
{
    tls_sample::TlsRequest driverRequest;
    driverRequest.serverName = request.server_name;
    driverRequest.serverPort = request.server_port;
    driverRequest.httpPath = request.http_path;
    driverRequest.inputValue = request.input_value;
    driverRequest.maxResponseBytes = request.max_response_bytes;

    if (request.pinned_server_certificate_sha256.size() != driverRequest.pinnedServerCertificateSha256.size())
    {
        result.status = TlsSampleStatus::TlsSampleStatus_AccessDenied;
        result.diagnostics = "pinned_server_certificate_sha256 must be 32 bytes";
        return S_OK;
    }

    std::copy(
        request.pinned_server_certificate_sha256.begin(),
        request.pinned_server_certificate_sha256.end(),
        driverRequest.pinnedServerCertificateSha256.begin());

    tls_sample::TransportCallbacks callbacks;
    callbacks.connect = Connect;
    callbacks.recv = Recv;
    callbacks.send = Send;
    callbacks.close = Close;

    const auto driverResult = tls_sample::RunServerAuthScenario(driverRequest, callbacks);
    result.status = MapTlsStatus(driverResult.status);
    result.output_value = driverResult.outputValue;
    result.decision = driverResult.decision;
    result.diagnostics = driverResult.diagnostics;
    result.tls_version = driverResult.tlsVersion;
    result.cipher_suite = driverResult.cipherSuite;
    return S_OK;
}
