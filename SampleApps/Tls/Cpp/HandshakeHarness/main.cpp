// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "TlsMbedTlsDriver.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <filesystem>
#include <sstream>
#include <string>

namespace
{
    struct SocketContext
    {
        std::map<uint64_t, SOCKET> sockets;
        uint64_t nextHandle{1};
    };

    std::vector<uint8_t> ReadFileBytes(const std::string& path)
    {
        std::ifstream file(path, std::ios::binary);
        if (!file)
        {
            throw std::runtime_error("could not open certificate file: " + path);
        }
        return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
    }

    std::string HexDigest(const std::array<uint8_t, 32>& digest)
    {
        std::ostringstream stream;
        for (const auto value : digest)
        {
            stream << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(value);
        }
        return stream.str();
    }

    tls_sample::HostTcpConnectResult Connect(void* rawContext, const std::string& serverName, uint16_t serverPort)
    {
        auto& context = *static_cast<SocketContext*>(rawContext);
        tls_sample::HostTcpConnectResult result;

        addrinfo hints{};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        addrinfo* addresses{};
        const auto port = std::to_string(serverPort);
        if (getaddrinfo(serverName.c_str(), port.c_str(), &hints, &addresses) != 0)
        {
            result.status = tls_sample::HostIoStatus::Failed;
            result.hostError = WSAGetLastError();
            return result;
        }

        std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> addressesHolder(addresses, freeaddrinfo);
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
            result.status = tls_sample::HostIoStatus::Failed;
            result.hostError = WSAGetLastError();
            return result;
        }

        result.transportHandle = context.nextHandle++;
        context.sockets.emplace(result.transportHandle, socketHandle);
        result.status = tls_sample::HostIoStatus::Ok;
        return result;
    }

    tls_sample::HostTcpRecvResult Recv(void* rawContext, uint64_t transportHandle, uint32_t maxBytes)
    {
        auto& context = *static_cast<SocketContext*>(rawContext);
        tls_sample::HostTcpRecvResult result;
        auto it = context.sockets.find(transportHandle);
        if (it == context.sockets.end())
        {
            result.status = tls_sample::HostIoStatus::Failed;
            return result;
        }

        result.bytes.resize(maxBytes);
        const int received = recv(it->second, reinterpret_cast<char*>(result.bytes.data()), static_cast<int>(result.bytes.size()), 0);
        if (received > 0)
        {
            result.bytes.resize(static_cast<size_t>(received));
            result.status = tls_sample::HostIoStatus::Ok;
            return result;
        }
        result.bytes.clear();
        result.status = received == 0 ? tls_sample::HostIoStatus::Closed : tls_sample::HostIoStatus::Failed;
        result.hostError = received == 0 ? 0 : WSAGetLastError();
        return result;
    }

    tls_sample::HostIoResult Send(void* rawContext, uint64_t transportHandle, const uint8_t* bytes, uint32_t byteCount)
    {
        auto& context = *static_cast<SocketContext*>(rawContext);
        tls_sample::HostIoResult result;
        auto it = context.sockets.find(transportHandle);
        if (it == context.sockets.end())
        {
            result.status = tls_sample::HostIoStatus::Failed;
            return result;
        }

        const int sent = send(it->second, reinterpret_cast<const char*>(bytes), static_cast<int>(byteCount), 0);
        if (sent >= 0)
        {
            result.status = tls_sample::HostIoStatus::Ok;
            result.bytesTransferred = static_cast<uint32_t>(sent);
            return result;
        }
        result.status = tls_sample::HostIoStatus::Failed;
        result.hostError = WSAGetLastError();
        return result;
    }

    tls_sample::HostIoResult Close(void* rawContext, uint64_t transportHandle)
    {
        auto& context = *static_cast<SocketContext*>(rawContext);
        auto it = context.sockets.find(transportHandle);
        if (it != context.sockets.end())
        {
            closesocket(it->second);
            context.sockets.erase(it);
        }
        return {tls_sample::HostIoStatus::Ok, 0, 0};
    }

    std::string GetArg(int argc, char** argv, const std::string& name, const std::string& fallback)
    {
        for (int i = 1; i + 1 < argc; ++i)
        {
            if (argv[i] == name)
            {
                return argv[i + 1];
            }
        }
        return fallback;
    }
}

int main(int argc, char** argv)
{
    WSADATA wsaData{};
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        return 2;
    }

    const auto certPath = GetArg(argc, argv, "--cert", "..\\..\\TestServer\\test-certs\\server-cert.pem");
    const auto serverName = GetArg(argc, argv, "--server", "localhost");
    const auto path = GetArg(argc, argv, "--path", "/secret-config");
    const auto port = static_cast<uint16_t>(std::stoi(GetArg(argc, argv, "--port", "8443")));
    const auto input = static_cast<uint32_t>(std::stoul(GetArg(argc, argv, "--input", "38")));

    SocketContext socketContext;
    tls_sample::TransportCallbacks callbacks{
        &socketContext,
        Connect,
        Recv,
        Send,
        Close,
    };

    tls_sample::TlsRequest request;
    request.serverName = serverName;
    request.serverPort = port;
    request.httpPath = path;
    request.inputValue = input;
    try
    {
        request.pinnedServerCertificateSha256 = tls_sample::ComputeCertificateSha256(ReadFileBytes(certPath));
    }
    catch (const std::exception& error)
    {
        std::cerr << error.what() << "\n";
        WSACleanup();
        return 3;
    }

    if (tls_sample::IsEmptySha256(request.pinnedServerCertificateSha256))
    {
        std::cerr << "could not parse certificate file: " << certPath << "\n";
        WSACleanup();
        return 4;
    }

    std::cout << "cert_path=" << std::filesystem::absolute(certPath).string() << "\n";
    std::cout << "pinned_cert_sha256=" << HexDigest(request.pinnedServerCertificateSha256) << "\n";

    const auto result = tls_sample::RunServerAuthScenario(request, callbacks);
    WSACleanup();

    std::cout << "status=" << static_cast<uint32_t>(result.status) << "\n";
    std::cout << "decision=" << result.decision << "\n";
    std::cout << "output_value=" << result.outputValue << "\n";
    std::cout << "diagnostics=" << result.diagnostics << "\n";
    std::cout << "tls_version=0x" << std::hex << result.tlsVersion << "\n";
    std::cout << "cipher_suite=0x" << std::hex << result.cipherSuite << "\n";

    if (result.status != tls_sample::TlsSampleStatus::Ok ||
        result.outputValue != input * 37 ||
        result.decision.find("sample-server-only-value") != std::string::npos ||
        result.diagnostics.find("sample-server-only-value") != std::string::npos)
    {
        return 1;
    }
    return 0;
}
