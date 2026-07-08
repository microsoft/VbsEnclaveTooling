// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "TlsMbedTlsDriver.h"
#include "ScenarioPolicy.g.h"

#include <cstring>
#include <memory>
#include <unordered_map>
#include <vector>

#include <VbsEnclave\Enclave\Abi\Exports.TlsTransport.cpp>
#include <VbsEnclave\Enclave\Implementation\Trusted.h>
#include <VbsEnclave\Enclave\Stubs\Untrusted.h>

namespace
{
    using namespace TlsSample::Types;

    // The driver enums intentionally mirror the EDL enums value-for-value, so
    // conversion is a checked cast rather than a hand-maintained switch.
    template <typename To, typename From>
    To CastEnum(From value)
    {
        return static_cast<To>(static_cast<std::uint32_t>(value));
    }

    tls_sample::HostTcpConnectResult Connect(void*, const std::string& serverName, uint16_t serverPort)
    {
        auto r = TlsSample::Untrusted::Stubs::TlsSample_HostTcpConnect(serverName, serverPort);
        return {CastEnum<tls_sample::HostIoStatus>(r.status), r.transport_handle, r.host_error};
    }

    tls_sample::HostTcpRecvResult Recv(void*, uint64_t transportHandle, uint32_t maxBytes)
    {
        auto r = TlsSample::Untrusted::Stubs::TlsSample_HostTcpRecv(transportHandle, maxBytes);
        return {CastEnum<tls_sample::HostIoStatus>(r.status), std::move(r.bytes), r.host_error};
    }

    tls_sample::HostIoResult Send(void*, uint64_t transportHandle, const uint8_t* bytes, uint32_t byteCount)
    {
        std::vector<uint8_t> payload(bytes, bytes + byteCount);
        auto r = TlsSample::Untrusted::Stubs::TlsSample_HostTcpSend(transportHandle, payload);
        return {CastEnum<tls_sample::HostIoStatus>(r.status), r.bytes_transferred, r.host_error};
    }

    tls_sample::HostIoResult Close(void*, uint64_t transportHandle)
    {
        auto r = TlsSample::Untrusted::Stubs::TlsSample_HostTcpClose(transportHandle);
        return {CastEnum<tls_sample::HostIoStatus>(r.status), r.bytes_transferred, r.host_error};
    }

    tls_sample::TransportCallbacks MakeCallbacks()
    {
        tls_sample::TransportCallbacks callbacks;
        callbacks.connect = Connect;
        callbacks.recv = Recv;
        callbacks.send = Send;
        callbacks.close = Close;
        return callbacks;
    }

    // Enclave-owned scenario policy. VTL0 selects a scenario by id but never
    // supplies target, path, pin, or limits. The pin and endpoint are fixed into
    // the enclave image at build time (ScenarioPolicy.g.h).
    const tls_sample::ScenarioPolicy* FindScenario(uint32_t scenarioId)
    {
        static const std::vector<tls_sample::ScenarioPolicy> table = [] {
            tls_sample::ScenarioPolicy serverAuth;
            serverAuth.scenarioId = 0;
            serverAuth.connectHost = tls_sample_generated::k_scenario0_connect_host;
            serverAuth.connectPort = tls_sample_generated::k_scenario0_connect_port;
            serverAuth.tlsServerName = tls_sample_generated::k_scenario0_tls_server_name;
            serverAuth.httpPath = tls_sample_generated::k_scenario0_http_path;
            serverAuth.maxResponseBytes = 16 * 1024;
            std::memcpy(
                serverAuth.pinnedCertificateSha256.data(),
                tls_sample_generated::k_scenario0_certificate_sha256,
                serverAuth.pinnedCertificateSha256.size());
            return std::vector<tls_sample::ScenarioPolicy>{serverAuth};
        }();

        for (const auto& scenario : table)
        {
            if (scenario.scenarioId == scenarioId)
            {
                return &scenario;
            }
        }
        return nullptr;
    }

    // Session-handle table. Handles are monotonic and never reused, so a stale
    // handle can never alias a live session. The sample drives one scenario to
    // completion at a time on a single enclave thread (mirroring the single-
    // threaded PSA-crypto contract), so no locking is required here.
    std::unordered_map<uint64_t, std::unique_ptr<tls_sample::TlsSession>> g_sessions;
    uint64_t g_nextSessionHandle = 1;
}

HRESULT TlsSample::Trusted::Implementation::TlsSample_GetScenarioMetadata(
    _In_ std::uint32_t scenario_id,
    _Out_ TlsSampleScenarioMetadata& metadata)
{
    metadata = {};
    metadata.scenario_id = scenario_id;

    const auto* scenario = FindScenario(scenario_id);
    if (!scenario)
    {
        metadata.status = TlsSampleStatus::TlsSampleStatus_UnknownScenario;
        return S_OK;
    }

    metadata.status = TlsSampleStatus::TlsSampleStatus_Ok;
    metadata.profile = TlsSampleProfile::TlsSampleProfile_ServerAuth;
    metadata.connect_host = scenario->connectHost;
    metadata.connect_port = scenario->connectPort;
    metadata.tls_server_name = scenario->tlsServerName;
    metadata.http_path = scenario->httpPath;
    metadata.max_response_bytes = scenario->maxResponseBytes;
    std::copy(
        scenario->pinnedCertificateSha256.begin(),
        scenario->pinnedCertificateSha256.end(),
        metadata.pinned_certificate_sha256.begin());
    return S_OK;
}

HRESULT TlsSample::Trusted::Implementation::TlsSample_StartScenario(
    _In_ const TlsSampleRequest& request,
    _Out_ StartScenarioResult& result)
{
    result = {};

    const auto* scenario = FindScenario(request.scenario_id);
    if (!scenario)
    {
        result.status = TlsSampleStatus::TlsSampleStatus_UnknownScenario;
        return S_OK;
    }

    auto session = std::make_unique<tls_sample::TlsSession>(*scenario, request.input_value, MakeCallbacks());

    const uint64_t handle = g_nextSessionHandle++;
    g_sessions.emplace(handle, std::move(session));
    result.status = TlsSampleStatus::TlsSampleStatus_Ok;
    result.session_handle = handle;
    return S_OK;
}

HRESULT TlsSample::Trusted::Implementation::TlsSample_DriveConnection(
    _In_ std::uint64_t session_handle,
    _Out_ DriveConnectionResult& result)
{
    result = {};

    tls_sample::TlsSession* session = nullptr;
    {
        auto it = g_sessions.find(session_handle);
        if (it == g_sessions.end())
        {
            result.progress = TlsSampleProgress::TlsSampleProgress_Failed;
            result.status = TlsSampleStatus::TlsSampleStatus_InvalidHandle;
            return S_OK;
        }
        session = it->second.get();
    }

    const auto progress = session->Drive();
    result.progress = CastEnum<TlsSampleProgress>(progress);
    result.status = CastEnum<TlsSampleStatus>(session->Result().status);
    return S_OK;
}

HRESULT TlsSample::Trusted::Implementation::TlsSample_GetDerivedResult(
    _In_ std::uint64_t session_handle,
    _Out_ TlsSampleResult& result)
{
    result = {};

    auto it = g_sessions.find(session_handle);
    if (it == g_sessions.end())
    {
        result.status = TlsSampleStatus::TlsSampleStatus_InvalidHandle;
        result.failure_reason = TlsSampleStatus::TlsSampleStatus_InvalidHandle;
        return S_OK;
    }

    const auto& driverResult = it->second->Result();
    result.status = CastEnum<TlsSampleStatus>(driverResult.status);
    result.decision = CastEnum<TlsSampleDecision>(driverResult.decision);
    result.output_value = driverResult.outputValue;
    result.tls_version = driverResult.tlsVersion;
    result.cipher_suite = driverResult.cipherSuite;
    result.failure_reason = CastEnum<TlsSampleStatus>(driverResult.failureReason);
    return S_OK;
}

HRESULT TlsSample::Trusted::Implementation::TlsSample_CloseScenario(_In_ std::uint64_t session_handle)
{
    g_sessions.erase(session_handle);
    return S_OK;
}
