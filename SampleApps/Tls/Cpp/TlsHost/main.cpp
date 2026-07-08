// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
//
// Enclave host: loads the TLS enclave, registers the transport callbacks, then
// selects a scenario by id and drives the enclave's TLS state machine to
// completion. The host supplies only transport (sockets); the enclave owns the
// server identity policy (target, SNI, HTTP path, certificate pin, limits).

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <array>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <map>
#include <string>
#include <thread>

#include <wil/resource.h>
#include <wil/result_macros.h>

#include <VbsEnclave\HostApp\Implementation\Untrusted.h>
#include <VbsEnclave\HostApp\Stubs\Trusted.h>

namespace
{
    std::map<uint64_t, SOCKET> g_sockets;
    uint64_t g_nextHandle = 1;

    wil::unique_any<void*, decltype(&DeleteEnclave), DeleteEnclave> CreateAndLoadEnclave(const std::filesystem::path& enclavePath)
    {
        std::array<uint8_t, IMAGE_ENCLAVE_LONG_ID_LENGTH> ownerId{};
        ENCLAVE_CREATE_INFO_VBS createInfo{};
        // The debug flag lets the (untrusted) containing process inspect enclave
        // memory, so only enable it for debug builds; a release build creates a
        // production enclave that preserves the VTL0/VTL1 isolation boundary.
#ifdef _DEBUG
        createInfo.Flags = ENCLAVE_VBS_FLAG_DEBUG;
#endif
        std::memcpy(createInfo.OwnerID, ownerId.data(), ownerId.size());

        void* enclave = CreateEnclave(
            GetCurrentProcess(),
            nullptr,
            512ull * 1024 * 1024,
            0,
            ENCLAVE_TYPE_VBS,
            &createInfo,
            sizeof(createInfo),
            nullptr);
        THROW_LAST_ERROR_IF_NULL(enclave);
        wil::unique_any<void*, decltype(&DeleteEnclave), DeleteEnclave> holder(enclave);

        THROW_IF_WIN32_BOOL_FALSE(LoadEnclaveImageW(enclave, enclavePath.c_str()));

        ENCLAVE_INIT_INFO_VBS initInfo{};
        initInfo.Length = sizeof(initInfo);
        initInfo.ThreadCount = 2;
        THROW_IF_WIN32_BOOL_FALSE(InitializeEnclave(GetCurrentProcess(), enclave, &initInfo, sizeof(initInfo), nullptr));
        return holder;
    }
}

TlsSample::Types::HostTcpConnectResult TlsSample::Untrusted::Implementation::TlsSample_HostTcpConnect(
    _In_ const std::string& server_name,
    _In_ std::uint16_t server_port)
{
    TlsSample::Types::HostTcpConnectResult result;
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* addresses{};
    const auto port = std::to_string(server_port);
    const int gaiResult = getaddrinfo(server_name.c_str(), port.c_str(), &hints, &addresses);
    if (gaiResult != 0)
    {
        result.status = TlsSample::Types::HostIoStatus::HostIoStatus_Failed;
        result.host_error = static_cast<uint32_t>(gaiResult);
        return result;
    }

    std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> holder(addresses, freeaddrinfo);
    SOCKET socketHandle = INVALID_SOCKET;
    for (auto* address = addresses; address; address = address->ai_next)
    {
        socketHandle = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
        if (socketHandle == INVALID_SOCKET)
        {
            continue;
        }
        if (connect(socketHandle, address->ai_addr, static_cast<int>(address->ai_addrlen)) == 0)
        {
            break;
        }
        closesocket(socketHandle);
        socketHandle = INVALID_SOCKET;
    }

    if (socketHandle == INVALID_SOCKET)
    {
        result.status = TlsSample::Types::HostIoStatus::HostIoStatus_Failed;
        result.host_error = WSAGetLastError();
        return result;
    }

    // Non-blocking so the enclave's DriveConnection sees WouldBlock and retains
    // control instead of blocking inside a host recv/send.
    u_long nonBlocking = 1;
    ioctlsocket(socketHandle, FIONBIO, &nonBlocking);

    result.transport_handle = g_nextHandle++;
    g_sockets.emplace(result.transport_handle, socketHandle);
    result.status = TlsSample::Types::HostIoStatus::HostIoStatus_Ok;
    return result;
}

TlsSample::Types::HostTcpRecvResult TlsSample::Untrusted::Implementation::TlsSample_HostTcpRecv(
    _In_ std::uint64_t transport_handle,
    _In_ std::uint32_t max_bytes)
{
    TlsSample::Types::HostTcpRecvResult result;
    auto it = g_sockets.find(transport_handle);
    if (it == g_sockets.end())
    {
        result.status = TlsSample::Types::HostIoStatus::HostIoStatus_Failed;
        return result;
    }

    result.bytes.resize(max_bytes);
    const int received = recv(it->second, reinterpret_cast<char*>(result.bytes.data()), static_cast<int>(result.bytes.size()), 0);
    if (received > 0)
    {
        result.bytes.resize(static_cast<size_t>(received));
        result.status = TlsSample::Types::HostIoStatus::HostIoStatus_Ok;
        return result;
    }

    result.bytes.clear();
    if (received == 0)
    {
        result.status = TlsSample::Types::HostIoStatus::HostIoStatus_Closed;
        return result;
    }

    const int error = WSAGetLastError();
    result.status = (error == WSAEWOULDBLOCK)
        ? TlsSample::Types::HostIoStatus::HostIoStatus_WouldBlock
        : TlsSample::Types::HostIoStatus::HostIoStatus_Failed;
    result.host_error = static_cast<uint32_t>(error);
    return result;
}

TlsSample::Types::HostIoResult TlsSample::Untrusted::Implementation::TlsSample_HostTcpSend(
    _In_ std::uint64_t transport_handle,
    _In_ const std::vector<std::uint8_t>& bytes)
{
    TlsSample::Types::HostIoResult result;
    auto it = g_sockets.find(transport_handle);
    if (it == g_sockets.end())
    {
        result.status = TlsSample::Types::HostIoStatus::HostIoStatus_Failed;
        return result;
    }

    const int sent = send(it->second, reinterpret_cast<const char*>(bytes.data()), static_cast<int>(bytes.size()), 0);
    if (sent >= 0)
    {
        result.status = TlsSample::Types::HostIoStatus::HostIoStatus_Ok;
        result.bytes_transferred = static_cast<uint32_t>(sent);
        return result;
    }

    const int error = WSAGetLastError();
    result.status = (error == WSAEWOULDBLOCK)
        ? TlsSample::Types::HostIoStatus::HostIoStatus_WouldBlock
        : TlsSample::Types::HostIoStatus::HostIoStatus_Failed;
    result.host_error = static_cast<uint32_t>(error);
    return result;
}

TlsSample::Types::HostIoResult TlsSample::Untrusted::Implementation::TlsSample_HostTcpClose(_In_ std::uint64_t transport_handle)
{
    auto it = g_sockets.find(transport_handle);
    if (it != g_sockets.end())
    {
        closesocket(it->second);
        g_sockets.erase(it);
    }
    return {TlsSample::Types::HostIoStatus::HostIoStatus_Ok, 0, 0};
}

int main(int argc, char** argv)
try
{
    using namespace TlsSample::Types;

    const std::filesystem::path enclavePath = argc > 1 ? argv[1] : "TlsEnclave.dll";
    const uint32_t scenarioId = argc > 2 ? static_cast<uint32_t>(std::stoul(argv[2])) : 0;
    const uint32_t input = argc > 3 ? static_cast<uint32_t>(std::stoul(argv[3])) : 38;

    WSADATA wsaData{};
    THROW_IF_WIN32_ERROR(WSAStartup(MAKEWORD(2, 2), &wsaData));
    auto cleanupWsa = wil::scope_exit([] { WSACleanup(); });

    auto enclave = CreateAndLoadEnclave(enclavePath);
    auto enclaveInterface = TlsSample::Trusted::Stubs::TlsSampleHost(enclave.get());
    THROW_IF_FAILED(enclaveInterface.RegisterVtl0Callbacks());

    // The enclave owns the policy; the host can display it but not change it.
    TlsSampleScenarioMetadata metadata{};
    THROW_IF_FAILED(enclaveInterface.TlsSample_GetScenarioMetadata(scenarioId, metadata));
    if (metadata.status != TlsSampleStatus::TlsSampleStatus_Ok)
    {
        std::cerr << "unknown scenario " << scenarioId << "\n";
        return 1;
    }
    std::cout << "scenario_id=" << metadata.scenario_id << "\n";
    std::cout << "connect=" << metadata.connect_host << ":" << metadata.connect_port << "\n";
    std::cout << "tls_server_name=" << metadata.tls_server_name << "\n";
    std::cout << "http_path=" << metadata.http_path << "\n";

    TlsSampleRequest request{};
    request.scenario_id = scenarioId;
    request.input_value = input;

    StartScenarioResult started{};
    THROW_IF_FAILED(enclaveInterface.TlsSample_StartScenario(request, started));
    if (started.status != TlsSampleStatus::TlsSampleStatus_Ok)
    {
        std::cerr << "start failed status=" << static_cast<uint32_t>(started.status) << "\n";
        return 1;
    }

    // Blocking-for-demo loop: drive the enclave until it completes or fails.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    DriveConnectionResult drive{};
    bool completed = false;
    for (;;)
    {
        THROW_IF_FAILED(enclaveInterface.TlsSample_DriveConnection(started.session_handle, drive));
        if (drive.progress == TlsSampleProgress::TlsSampleProgress_Completed)
        {
            completed = true;
            break;
        }
        if (drive.progress == TlsSampleProgress::TlsSampleProgress_Failed)
        {
            break;
        }
        if (std::chrono::steady_clock::now() > deadline)
        {
            std::cerr << "timed out driving the enclave scenario\n";
            break;
        }
        if (drive.progress == TlsSampleProgress::TlsSampleProgress_WouldBlock)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    TlsSampleResult result{};
    THROW_IF_FAILED(enclaveInterface.TlsSample_GetDerivedResult(started.session_handle, result));
    THROW_IF_FAILED(enclaveInterface.TlsSample_CloseScenario(started.session_handle));

    std::cout << "status=" << static_cast<uint32_t>(result.status) << "\n";
    std::cout << "decision=" << (result.decision == TlsSampleDecision::TlsSampleDecision_Allow ? "Allow" : "Deny") << "\n";
    std::cout << "output_value=" << result.output_value << "\n";
    std::cout << "failure_reason=" << static_cast<uint32_t>(result.failure_reason) << "\n";
    std::cout << "tls_version=0x" << std::hex << result.tls_version << std::dec << "\n";
    std::cout << "cipher_suite=0x" << std::hex << result.cipher_suite << std::dec << "\n";

    // Only a scenario that actually ran to completion and returned Ok is success.
    return (completed && result.status == TlsSampleStatus::TlsSampleStatus_Ok) ? 0 : 1;
}
catch (...)
{
    std::cerr << "failure: 0x" << std::hex << wil::ResultFromCaughtException() << "\n";
    return 1;
}
