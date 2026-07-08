// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "TlsMbedTlsDriver.h"
#include "ScenarioPolicy.g.h"

#include <atomic>
#include <cstring>
#include <memory>
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
    TLS_SAMPLE_ASSERT_ENUM(tls_sample::TlsSampleStatus::InvalidHandle, TlsSampleStatus::TlsSampleStatus_InvalidHandle);
    TLS_SAMPLE_ASSERT_ENUM(tls_sample::TlsSampleStatus::InvalidState, TlsSampleStatus::TlsSampleStatus_InvalidState);
    TLS_SAMPLE_ASSERT_ENUM(tls_sample::TlsSampleStatus::UnknownScenario, TlsSampleStatus::TlsSampleStatus_UnknownScenario);
    TLS_SAMPLE_ASSERT_ENUM(tls_sample::TlsSampleProgress::Working, TlsSampleProgress::TlsSampleProgress_Working);
    TLS_SAMPLE_ASSERT_ENUM(tls_sample::TlsSampleProgress::WouldBlock, TlsSampleProgress::TlsSampleProgress_WouldBlock);
    TLS_SAMPLE_ASSERT_ENUM(tls_sample::TlsSampleProgress::Completed, TlsSampleProgress::TlsSampleProgress_Completed);
    TLS_SAMPLE_ASSERT_ENUM(tls_sample::TlsSampleProgress::Failed, TlsSampleProgress::TlsSampleProgress_Failed);
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

    // Single active session.
    //
    // The untrusted host controls call threading and the enclave is initialised
    // with more than one thread, so the trusted entrypoints must not assume
    // single-threaded entry. Rather than a concurrent-safe session table, the
    // sample enforces the simplest contract that keeps the enclave safe: at most
    // one TLS session exists at a time (a second StartScenario is rejected), and
    // all access to it is serialised.
    //
    // A small enclave-compatible spinlock (std::atomic_flag — the enclave CRT has
    // no std::mutex) guards the slot for SHORT critical sections only; it is never
    // held across TlsSession::Drive() (which re-enters VTL0). A `driving` flag
    // rejects concurrent Drive/read of the same session, and a close requested
    // while a drive is in flight is deferred so the session is never destroyed
    // (and its VTL0 close callback never runs) under the lock or beneath a drive.
    std::unique_ptr<tls_sample::TlsSession> g_session;
    uint64_t g_sessionHandle = 0;
    bool g_driving = false;
    bool g_closeRequested = false;
    uint64_t g_nextSessionHandle = 1;
    std::atomic_flag g_sessionLock = ATOMIC_FLAG_INIT;

    struct SpinGuard
    {
        SpinGuard() { while (g_sessionLock.test_and_set(std::memory_order_acquire)) {} }
        ~SpinGuard() { g_sessionLock.clear(std::memory_order_release); }
        SpinGuard(const SpinGuard&) = delete;
        SpinGuard& operator=(const SpinGuard&) = delete;
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

    SpinGuard guard;
    if (g_session)
    {
        // Only one session at a time: reject rather than run two mbedTLS/PSA
        // sessions concurrently against shared global crypto state.
        result.status = TlsSampleStatus::TlsSampleStatus_AccessDenied;
        return S_OK;
    }
    g_session = std::move(session);
    g_sessionHandle = g_nextSessionHandle++;
    g_driving = false;
    g_closeRequested = false;
    result.status = TlsSampleStatus::TlsSampleStatus_Ok;
    result.session_handle = g_sessionHandle;
    return S_OK;
}

HRESULT TlsSample::Trusted::Implementation::TlsSample_DriveConnection(
    _In_ std::uint64_t session_handle,
    _Out_ DriveConnectionResult& result)
{
    result = {};

    tls_sample::TlsSession* session = nullptr;
    {
        SpinGuard guard;
        if (!g_session || session_handle != g_sessionHandle)
        {
            result.progress = TlsSampleProgress::TlsSampleProgress_Failed;
            result.status = TlsSampleStatus::TlsSampleStatus_InvalidHandle;
            return S_OK;
        }
        if (g_driving)
        {
            // Another thread is already driving this session; reject the
            // concurrent re-entry rather than race the mbedTLS state machine.
            result.progress = TlsSampleProgress::TlsSampleProgress_Failed;
            result.status = TlsSampleStatus::TlsSampleStatus_InvalidState;
            return S_OK;
        }
        g_driving = true;
        session = g_session.get();  // stays alive: close is deferred while driving
    }

    // Drive() re-enters VTL0 via transport callbacks — run it outside the lock.
    const auto progress = session->Drive();
    const auto status = session->Result().status;

    std::unique_ptr<tls_sample::TlsSession> expired;
    {
        SpinGuard guard;
        g_driving = false;
        if (g_closeRequested)
        {
            // A close arrived mid-drive; complete it now by moving the session
            // out so it destructs (and runs its VTL0 close) outside the lock.
            expired = std::move(g_session);
            g_sessionHandle = 0;
            g_closeRequested = false;
        }
    }

    result.progress = CastEnum<TlsSampleProgress>(progress);
    result.status = CastEnum<TlsSampleStatus>(status);
    return S_OK;
}

HRESULT TlsSample::Trusted::Implementation::TlsSample_GetDerivedResult(
    _In_ std::uint64_t session_handle,
    _Out_ TlsSampleResult& result)
{
    result = {};

    SpinGuard guard;
    if (!g_session || session_handle != g_sessionHandle)
    {
        result.status = TlsSampleStatus::TlsSampleStatus_InvalidHandle;
        result.failure_reason = TlsSampleStatus::TlsSampleStatus_InvalidHandle;
        return S_OK;
    }
    if (g_driving)
    {
        // A drive is writing the result concurrently; refuse to read a torn value.
        result.status = TlsSampleStatus::TlsSampleStatus_InvalidState;
        result.failure_reason = TlsSampleStatus::TlsSampleStatus_InvalidState;
        return S_OK;
    }

    const auto& driverResult = g_session->Result();
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
    std::unique_ptr<tls_sample::TlsSession> expired;
    {
        SpinGuard guard;
        if (!g_session || session_handle != g_sessionHandle)
        {
            return S_OK;
        }
        if (g_driving)
        {
            // Cannot destroy a session that is mid-drive; defer to the drive's
            // completion so its VTL0 close callback never runs under a drive.
            g_closeRequested = true;
            return S_OK;
        }
        expired = std::move(g_session);  // destructs below, after the lock is released
        g_sessionHandle = 0;
    }
    return S_OK;
}
