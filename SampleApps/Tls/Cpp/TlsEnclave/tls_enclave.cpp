// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// wil_for_enclaves.h must precede any Windows header (pulled in transitively by
// the generated ABI headers below), so include it explicitly first.
#include <wil/enclave/wil_for_enclaves.h>

#include "TlsMbedTlsDriver.h"
#include "ScenarioPolicy.g.h"

#include <atomic>
#include <cstring>
#include <memory>
#include <vector>

#include <VbsEnclave\Enclave\Implementation\Trusted.h>
#include <VbsEnclave\Enclave\Stubs\Untrusted.h>

namespace
{
    using namespace TlsSample::Types;

    // The driver enums (tls_sample::*) intentionally mirror the generated EDL
    // enums value-for-value, so conversion is a direct cast. These static_asserts
    // fail the build if the EDL is ever reordered out of sync with the driver.
    // Every value CastEnum relies on is asserted so a mid-enum insertion cannot
    // silently misalign.
#define TLS_SAMPLE_ASSERT_ENUM(a, b) static_assert(static_cast<uint32_t>(a) == static_cast<uint32_t>(b))
    TLS_SAMPLE_ASSERT_ENUM(tls_sample::TlsSampleStatus::Ok, TlsSampleStatus::TlsSampleStatus_Ok);
    TLS_SAMPLE_ASSERT_ENUM(tls_sample::TlsSampleStatus::Closed, TlsSampleStatus::TlsSampleStatus_Closed);
    TLS_SAMPLE_ASSERT_ENUM(tls_sample::TlsSampleStatus::Truncated, TlsSampleStatus::TlsSampleStatus_Truncated);
    TLS_SAMPLE_ASSERT_ENUM(tls_sample::TlsSampleStatus::ValidationFailed, TlsSampleStatus::TlsSampleStatus_ValidationFailed);
    TLS_SAMPLE_ASSERT_ENUM(tls_sample::TlsSampleStatus::TransportFailed, TlsSampleStatus::TlsSampleStatus_TransportFailed);
    TLS_SAMPLE_ASSERT_ENUM(tls_sample::TlsSampleStatus::ProtocolFailed, TlsSampleStatus::TlsSampleStatus_ProtocolFailed);
    TLS_SAMPLE_ASSERT_ENUM(tls_sample::TlsSampleStatus::AccessDenied, TlsSampleStatus::TlsSampleStatus_AccessDenied);
    TLS_SAMPLE_ASSERT_ENUM(tls_sample::TlsSampleStatus::BudgetExceeded, TlsSampleStatus::TlsSampleStatus_BudgetExceeded);
    TLS_SAMPLE_ASSERT_ENUM(tls_sample::TlsSampleStatus::InvalidState, TlsSampleStatus::TlsSampleStatus_InvalidState);
    TLS_SAMPLE_ASSERT_ENUM(tls_sample::TlsSampleStatus::UnknownScenario, TlsSampleStatus::TlsSampleStatus_UnknownScenario);
    TLS_SAMPLE_ASSERT_ENUM(tls_sample::TlsSampleDecision::Deny, TlsSampleDecision::TlsSampleDecision_Deny);
    TLS_SAMPLE_ASSERT_ENUM(tls_sample::TlsSampleDecision::Allow, TlsSampleDecision::TlsSampleDecision_Allow);
    TLS_SAMPLE_ASSERT_ENUM(tls_sample::HostIoStatus::Ok, HostIoStatus::HostIoStatus_Ok);
    TLS_SAMPLE_ASSERT_ENUM(tls_sample::HostIoStatus::WouldBlock, HostIoStatus::HostIoStatus_WouldBlock);
    TLS_SAMPLE_ASSERT_ENUM(tls_sample::HostIoStatus::Closed, HostIoStatus::HostIoStatus_Closed);
    TLS_SAMPLE_ASSERT_ENUM(tls_sample::HostIoStatus::Failed, HostIoStatus::HostIoStatus_Failed);
#undef TLS_SAMPLE_ASSERT_ENUM

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

    // Admission guard: the enclave is passive and may be entered on any VTL0
    // thread, and a malicious VTL0 can attempt to re-enter RunScenario on the
    // reused physical thread WHILE the enclave is out in a transport ocall. Two
    // overlapping runs would race the process-global mbedTLS/PSA state (including
    // a double PSA free). A single non-spinning admission flag rejects any
    // concurrent/nested entry with AccessDenied. It must NOT spin (a spin held
    // across an ocall would deadlock the nested entry on the same physical
    // thread) and must not be thread_local (nested entry may land on a different
    // enclave thread slot).
    std::atomic_flag g_running = ATOMIC_FLAG_INIT;

    // Releases the admission flag on scope exit. It is declared BEFORE the
    // TlsSession in RunScenario, so the session (and its final transport-close
    // ocall in the destructor) is torn down while the flag is still held.
    struct RunGuard
    {
        RunGuard() = default;
        ~RunGuard() { g_running.clear(std::memory_order_release); }
        RunGuard(const RunGuard&) = delete;
        RunGuard& operator=(const RunGuard&) = delete;
    };
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

HRESULT TlsSample::Trusted::Implementation::TlsSample_RunScenario(
    _In_ const TlsSampleRequest& request,
    _Out_ TlsSampleResult& result)
{
    result = {};
    result.status = TlsSampleStatus::TlsSampleStatus_InvalidState;
    result.failure_reason = TlsSampleStatus::TlsSampleStatus_InvalidState;

    // Reject any concurrent or re-entrant run (see g_running above). test_and_set
    // returns the prior value: true means a run already holds the flag.
    if (g_running.test_and_set(std::memory_order_acquire))
    {
        result.status = TlsSampleStatus::TlsSampleStatus_AccessDenied;
        result.failure_reason = TlsSampleStatus::TlsSampleStatus_AccessDenied;
        return S_OK;
    }
    RunGuard guard;  // clears g_running after the session below is destroyed

    const auto* scenario = FindScenario(request.scenario_id);
    if (!scenario)
    {
        result.status = TlsSampleStatus::TlsSampleStatus_UnknownScenario;
        result.failure_reason = TlsSampleStatus::TlsSampleStatus_UnknownScenario;
        return S_OK;
    }

    // Runs the whole server-auth exchange to completion. The session owns all
    // mbedTLS/PSA state and closes the transport (an ocall) in its destructor,
    // which runs before RunGuard releases the admission flag.
    tls_sample::TlsSession session(*scenario, request.input_value, MakeCallbacks());
    session.Run();

    const auto& driverResult = session.Result();
    result.status = CastEnum<TlsSampleStatus>(driverResult.status);
    result.decision = CastEnum<TlsSampleDecision>(driverResult.decision);
    result.output_value = driverResult.outputValue;
    result.tls_version = driverResult.tlsVersion;
    result.cipher_suite = driverResult.cipherSuite;
    result.failure_reason = CastEnum<TlsSampleStatus>(driverResult.failureReason);
    return S_OK;
}
