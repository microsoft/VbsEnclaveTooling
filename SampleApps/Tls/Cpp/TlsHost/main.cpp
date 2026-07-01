// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <wil/resource.h>
#include <wil/result_macros.h>

#include <VbsEnclave\HostApp\Implementation\Untrusted.h>
#include <VbsEnclave\HostApp\Stubs\Trusted.h>

namespace
{
    std::map<uint64_t, SOCKET> g_sockets;
    uint64_t g_nextHandle = 1;

    std::vector<uint8_t> ReadFileBytes(const std::filesystem::path& path)
    {
        std::ifstream file(path, std::ios::binary);
        THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND), !file, "Could not open %ls", path.c_str());
        return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
    }

    std::vector<uint8_t> DecodePemCertificate(const std::vector<uint8_t>& pem)
    {
        DWORD decodedSize = 0;
        THROW_IF_WIN32_BOOL_FALSE(CryptStringToBinaryA(
            reinterpret_cast<LPCSTR>(pem.data()),
            static_cast<DWORD>(pem.size()),
            CRYPT_STRING_BASE64HEADER,
            nullptr,
            &decodedSize,
            nullptr,
            nullptr));

        std::vector<uint8_t> der(decodedSize);
        THROW_IF_WIN32_BOOL_FALSE(CryptStringToBinaryA(
            reinterpret_cast<LPCSTR>(pem.data()),
            static_cast<DWORD>(pem.size()),
            CRYPT_STRING_BASE64HEADER,
            der.data(),
            &decodedSize,
            nullptr,
            nullptr));
        der.resize(decodedSize);
        return der;
    }

    std::vector<uint8_t> Sha256(const std::vector<uint8_t>& bytes)
    {
        wil::unique_bcrypt_hash hash;
        THROW_IF_NTSTATUS_FAILED(BCryptCreateHash(BCRYPT_SHA256_ALG_HANDLE, &hash, nullptr, 0, nullptr, 0, 0));
        THROW_IF_NTSTATUS_FAILED(BCryptHashData(hash.get(), const_cast<PUCHAR>(bytes.data()), static_cast<ULONG>(bytes.size()), 0));

        std::vector<uint8_t> digest(32);
        THROW_IF_NTSTATUS_FAILED(BCryptFinishHash(hash.get(), digest.data(), static_cast<ULONG>(digest.size()), 0));
        return digest;
    }

    wil::unique_any<void*, decltype(&DeleteEnclave), DeleteEnclave> CreateAndLoadEnclave(const std::filesystem::path& enclavePath)
    {
        std::array<uint8_t, IMAGE_ENCLAVE_LONG_ID_LENGTH> ownerId{};
        ENCLAVE_CREATE_INFO_VBS createInfo{};
        createInfo.Flags = ENCLAVE_VBS_FLAG_DEBUG;
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
    if (getaddrinfo(server_name.c_str(), port.c_str(), &hints, &addresses) != 0)
    {
        result.status = TlsSample::Types::HostIoStatus::HostIoStatus_Failed;
        result.host_error = WSAGetLastError();
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
    result.status = received == 0 ? TlsSample::Types::HostIoStatus::HostIoStatus_Closed : TlsSample::Types::HostIoStatus::HostIoStatus_Failed;
    result.host_error = received == 0 ? 0 : WSAGetLastError();
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

    result.status = TlsSample::Types::HostIoStatus::HostIoStatus_Failed;
    result.host_error = WSAGetLastError();
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
    const std::filesystem::path enclavePath = argc > 1 ? argv[1] : "TlsEnclave.dll";
    const std::filesystem::path certPath = argc > 2 ? argv[2] : "..\\..\\TestServer\\test-certs\\server-cert.pem";
    const uint16_t port = argc > 3 ? static_cast<uint16_t>(std::stoi(argv[3])) : 9781;

    WSADATA wsaData{};
    const int wsaStartupResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    THROW_IF_WIN32_ERROR(wsaStartupResult);
    auto cleanupWsa = wil::scope_exit([] { WSACleanup(); });

    auto enclave = CreateAndLoadEnclave(enclavePath);
    auto enclaveInterface = TlsSample::Trusted::Stubs::TlsSampleHost(enclave.get());
    const HRESULT registerCallbacksResult = enclaveInterface.RegisterVtl0Callbacks();
    THROW_IF_FAILED(registerCallbacksResult);

    TlsSample::Types::TlsSampleRequest request;
    request.profile = TlsSample::Types::TlsSampleProfile::TlsSampleProfile_ServerAuth;
    request.server_name = "localhost";
    request.server_port = port;
    request.http_path = "/secret-config";
    request.input_value = 38;
    request.max_response_bytes = 16 * 1024;
    request.pinned_server_certificate_sha256 = Sha256(DecodePemCertificate(ReadFileBytes(certPath)));

    TlsSample::Types::TlsSampleResult result;
    const HRESULT runScenarioResult = enclaveInterface.TlsSample_RunScenario(request, result);
    THROW_IF_FAILED(runScenarioResult);

    std::cout << "status=" << static_cast<uint32_t>(result.status) << "\n";
    std::cout << "decision=" << result.decision << "\n";
    std::cout << "output_value=" << result.output_value << "\n";
    std::cout << "diagnostics=" << result.diagnostics << "\n";
    std::cout << "tls_version=0x" << std::hex << result.tls_version << "\n";
    std::cout << "cipher_suite=0x" << std::hex << result.cipher_suite << "\n";
    return result.status == TlsSample::Types::TlsSampleStatus::TlsSampleStatus_Ok ? 0 : 1;
}
catch (...)
{
    std::cerr << "failure: 0x" << std::hex << wil::ResultFromCaughtException() << "\n";
    return 1;
}
