// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "TlsMbedTlsDriver.h"
#include "ScenarioPolicy.g.h"

#include <atomic>
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

    // The driver enums (tls_sample::*) intentionally mirror the generated EDL
    // enums value-for-value, so conversion is a direct cast. These static_asserts
    // fail the build if the EDL is ever reordered out of sync with the driver.
    static_assert(static_cast<uint32_t>(tls_sample::TlsSampleStatus::Ok) == static_cast<uint32_t>(TlsSampleStatus::TlsSampleStatus_Ok));
    static_assert(static_cast<uint32_t>(tls_sample::TlsSampleStatus::ValidationFailed) == static_cast<uint32_t>(TlsSampleStatus::TlsSampleStatus_ValidationFailed));
    static_assert(static_cast<uint32_t>(tls_sample::TlsSampleStatus::UnknownScenario) == static_cast<uint32_t>(TlsSampleStatus::TlsSampleStatus_UnknownScenario));
    static_assert(static_cast<uint32_t>(tls_sample::TlsSampleStatus::InvalidHandle) == static_cast<uint32_t>(TlsSampleStatus::TlsSampleStatus_InvalidHandle));
    static_assert(static_cast<uint32_t>(tls_sample::TlsSampleProgress::Completed) == static_cast<uint32_t>(TlsSampleProgress::TlsSampleProgress_Completed));
    static_assert(static_cast<uint32_t>(tls_sample::TlsSampleProgress::Failed) == static_cast<uint32_t>(TlsSampleProgress::TlsSampleProgress_Failed));
    static_assert(static_cast<uint32_t>(tls_sample::TlsSampleDecision::Allow) == static_cast<uint32_t>(TlsSampleDecision::TlsSampleDecision_Allow));

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
    // handle can never alias a live session.
    //
    // The untrusted host controls call threading and the enclave is initialised
    // with more than one thread, so the trusted entrypoints must not assume
    // single-threaded entry. A small enclave-compatible spinlock (std::atomic_flag
    // — the enclave CRT has no std::mutex) guards the table and handle counter,
    // and sessions are held by shared_ptr so DriveConnection can keep its session
    // alive across the (VTL0-re-entering) Drive() call even if another thread
    // concurrently closes the same handle.
    std::unordered_map<uint64_t, std::shared_ptr<tls_sample::TlsSession>> g_sessions;
    uint64_t g_nextSessionHandle = 1;
    std::atomic_flag g_sessionsLock = ATOMIC_FLAG_INIT;

    struct SpinGuard
    {
        SpinGuard() { while (g_sessionsLock.test_and_set(std::memory_order_acquire)) {} }
        ~SpinGuard() { g_sessionsLock.clear(std::memory_order_release); }
        SpinGuard(const SpinGuard&) = delete;
        SpinGuard& operator=(const SpinGuard&) = delete;
    };

    std::shared_ptr<tls_sample::TlsSession> FindSession(uint64_t handle)
    {
        SpinGuard guard;
        auto it = g_sessions.find(handle);
        return it == g_sessions.end() ? nullptr : it->second;
    }
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

    auto session = std::make_shared<tls_sample::TlsSession>(*scenario, request.input_value, MakeCallbacks());

    SpinGuard guard;
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

    // Hold a shared_ptr for the duration of Drive() (which re-enters VTL0), so a
    // concurrent CloseScenario cannot free the session out from under us.
    auto session = FindSession(session_handle);
    if (!session)
    {
        result.progress = TlsSampleProgress::TlsSampleProgress_Failed;
        result.status = TlsSampleStatus::TlsSampleStatus_InvalidHandle;
        return S_OK;
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

    auto session = FindSession(session_handle);
    if (!session)
    {
        result.status = TlsSampleStatus::TlsSampleStatus_InvalidHandle;
        result.failure_reason = TlsSampleStatus::TlsSampleStatus_InvalidHandle;
        return S_OK;
    }

    const auto& driverResult = session->Result();
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
    SpinGuard guard;
    g_sessions.erase(session_handle);
    return S_OK;
}
