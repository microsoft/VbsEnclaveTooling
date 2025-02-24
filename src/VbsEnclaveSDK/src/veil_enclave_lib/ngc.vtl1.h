// Copyright (c) Microsoft Corporation. All rights reserved.

// TODO: PRIVATE APIs

// Brought over from OS.2020\onecore\ds\security\ngc\inc\ngcreqresp.h

#pragma once

#include <memory>
#include <array>
#include <vector>

namespace NgcReqResp
{

enum class Operation : uint32_t
{
    Undefined,
    ExportPublicKey,
    DeriveSharedSecret,
    GetCacheConfig,
    GetIsSecureIdOwnerId,
    CreateCounter,
    QueryCounter,
    IncrementCounter,
    GetIncrementedEphemeralCounter,
};

struct DeriveSharedSecretParams
{
    std::vector<uint8_t> publicKey;

    std::vector<uint8_t> ToVector() const
    {
        auto publicKeySize = static_cast<uint32_t>(publicKey.size());
        std::vector<uint8_t> output(sizeof(publicKeySize) + publicKeySize);
        memcpy(output.data(), &publicKeySize, sizeof(publicKeySize));
        memcpy(output.data() + sizeof(publicKeySize), publicKey.data(), publicKeySize);
        return output;
    }

    static DeriveSharedSecretParams FromVector(std::vector<uint8_t> input)
    {
        uint32_t publicKeySize = 0;
        THROW_HR_IF(NTE_BAD_DATA, input.size() <= sizeof(publicKeySize));
        memcpy(&publicKeySize, input.data(), sizeof(publicKeySize));

        THROW_HR_IF(NTE_BAD_DATA, input.size() < sizeof(publicKeySize) + publicKeySize);
        DeriveSharedSecretParams params{};
        params.publicKey.resize(publicKeySize);
        memcpy(params.publicKey.data(), input.data() + sizeof(publicKeySize), publicKeySize);

        return params;
    }
};

struct Request
{
    const std::array<uint8_t, 7> header = {"NgcReq"};
    Operation op;
    std::wstring keyName;
    void* params;

    Request() : params(nullptr) {};
    ~Request()
    {
        switch (op)
        {
        case Operation::DeriveSharedSecret:
        {
            if (params)
            {
                std::unique_ptr<DeriveSharedSecretParams> secretAgreementParams(reinterpret_cast<DeriveSharedSecretParams*>(params));
            }
            break;
        }
        default:
            break;
        }
    }

    Request(Request&& other) : op(other.op), keyName(std::move(other.keyName)), params(other.params)
    {
        other.params = nullptr;
    }
    Request& operator=(Request&& other)
    {
        op = other.op;
        keyName = std::move(other.keyName);
        params = other.params;
        other.params = nullptr;

        return *this;
    }

    Request(const Request&) = delete;
    Request& operator=(const Request&) = delete;

    std::vector<uint8_t> ToVector() const
    {
        std::vector<uint8_t> output{};
        output.insert(output.end(), header.data(), header.data() + header.size());
        output.insert(output.end(),
            reinterpret_cast<const uint8_t*>(&op),
            reinterpret_cast<const uint8_t*>(&op) + sizeof(op));

        uint32_t keyNameByteCount = static_cast<uint32_t>(keyName.size() * sizeof(wchar_t));
        output.insert(output.end(),
            reinterpret_cast<uint8_t*>(&keyNameByteCount),
            reinterpret_cast<uint8_t*>(&keyNameByteCount) + sizeof(keyNameByteCount));
        output.insert(output.end(),
            reinterpret_cast<const uint8_t*>(keyName.data()),
            reinterpret_cast<const uint8_t*>(keyName.data()) + keyNameByteCount);

        switch (op)
        {
        case Operation::DeriveSharedSecret:
        {
            auto serializedParams = reinterpret_cast<DeriveSharedSecretParams*>(params)->ToVector();
            output.insert(output.end(), serializedParams.begin(), serializedParams.end());
            break;
        }
        default:
            break;
        }

        return output;
    }

    static Request FromVector(const std::vector<uint8_t>& input)
    {
        Request request{};
        size_t index = 0;
        THROW_HR_IF(NTE_BAD_DATA, input.size() < request.header.size());
        THROW_HR_IF(NTE_BAD_TYPE, 0 != memcmp(request.header.data(), input.data(), request.header.size()));
        index += request.header.size();

        THROW_HR_IF(NTE_BAD_DATA, input.size() < index + sizeof(request.op));
        memcpy(&request.op, input.data() + index, sizeof(request.op));
        index += sizeof(request.op);

        uint32_t keyNameByteCount = 0;
        THROW_HR_IF(NTE_BAD_DATA, input.size() < index + sizeof(keyNameByteCount));
        memcpy(&keyNameByteCount, input.data() + index, sizeof(keyNameByteCount));
        index += sizeof(keyNameByteCount);

        THROW_HR_IF(NTE_BAD_DATA, input.size() < index + keyNameByteCount);
        request.keyName.assign(
            reinterpret_cast<const wchar_t*>(input.data() + index),
            reinterpret_cast<const wchar_t*>(input.data() + index + static_cast<size_t>(keyNameByteCount)));
        index += keyNameByteCount;

        switch (request.op)
        {
        case Operation::DeriveSharedSecret:
        {
            // params should be the remaining of the input buffer
            std::vector<uint8_t> serializedParams(input.begin() + index, input.end());
            auto params = std::make_unique<DeriveSharedSecretParams>(DeriveSharedSecretParams::FromVector(serializedParams));
            request.params = reinterpret_cast<void*>(params.release());
            break;
        }
        default:
            break;
        }

        return std::move(request);
    }
};

} /*NgcReqResp*/
