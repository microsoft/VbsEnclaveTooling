// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "pch.h"

#include <format>

#include <gsl/gsl_util>

#include <sddl.h>

#include "..\veil_any_inc\hello.any.h"
#include "..\veil_any_inc\utils.any.h"

#include "hello.vtl0.h"



namespace veil::vtl0::implementation::hello
{
    inline wil::unique_ncrypt_prov open_provider()
    {
        HWND hCurWnd = GetForegroundWindow();
        wil::unique_ncrypt_prov helloProvider;
        THROW_IF_FAILED(NCryptOpenStorageProvider(&helloProvider, MS_NGC_KEY_STORAGE_PROVIDER, 0));
        THROW_IF_NULL_ALLOC(helloProvider);
        return helloProvider;
    }

    inline bool is_key_exportable(const wil::unique_ncrypt_key& key)
    {
        DWORD permissions;
        DWORD permissionsSize;
        THROW_IF_FAILED(NCryptGetProperty(key.get(), NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&permissions, sizeof(permissions), &permissionsSize, 0));

        // Anything above 0 indicates that key is exportable in some form
        return permissions > 0;
    }

    inline void set_hello_key_prompt_message(NCRYPT_KEY_HANDLE key, std::wstring const& message)
    {
        NCRYPT_UI_POLICY uiPolicy {};
        uiPolicy.dwVersion = 1;
        uiPolicy.pszDescription = message.c_str();
        THROW_IF_FAILED(NCryptSetProperty(key, NCRYPT_UI_POLICY_PROPERTY, reinterpret_cast<PBYTE>(&uiPolicy), sizeof(NCRYPT_UI_POLICY), 0));
    }

    inline std::pair<wil::unique_ncrypt_key, bool> create_or_open_hello_key(NCRYPT_PROV_HANDLE provider, PCWSTR keyName, PCWSTR pinMessage, bool openOnly)
    {
        HWND hCurWnd = GetForegroundWindow();
        THROW_IF_FAILED(NCryptOpenStorageProvider(&provider, MS_NGC_KEY_STORAGE_PROVIDER, 0));

        THROW_IF_FAILED(NCryptSetProperty(provider, NCRYPT_WINDOW_HANDLE_PROPERTY, reinterpret_cast<PBYTE>(&hCurWnd), sizeof(hCurWnd), 0));

        // Try to open a transactional key pair.
        wil::unique_ncrypt_key helloKey;
        bool created = false;
        HRESULT hrOpen = NCryptOpenKey(provider, &helloKey, keyName, 0, 0);

        // Detect abnormalities when a key is found and opened successfully
        if (hrOpen == S_OK && helloKey)
        {
            // Mark key as compromised when key is exportable
            if (is_key_exportable(helloKey))
            {
                // Delete potentially compromised key set
                if (SUCCEEDED_LOG(NCryptDeleteKey(helloKey.get(), 0)))
                {
                    // NCryptDeleteKey frees the key on success, so release here to avoid double-free.
                    helloKey.release();
                }
                helloKey = nullptr;
            }
        }
        else
        {
            if (openOnly)
            {
                THROW_WIN32(ERROR_NOT_FOUND);
            }
        }

        // Key not found, or bad key - create a fresh one.
        if (hrOpen == NTE_NO_KEY || hrOpen == NTE_BAD_KEYSET || !helloKey)
        {
            THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_NOT_FOUND), openOnly);
            THROW_IF_FAILED(NCryptCreatePersistedKey(provider, &helloKey, NCRYPT_ECDH_P384_ALGORITHM, keyName, 0, NCRYPT_OVERWRITE_KEY_FLAG));
            created = true;
        }
        else
        {
            THROW_IF_FAILED(hrOpen);
        }

        THROW_IF_NULL_ALLOC(helloKey);

        set_hello_key_prompt_message(helloKey.get(), pinMessage);

        return {std::move(helloKey), created};
    }

    inline std::pair<wil::unique_ncrypt_key, bool> create_hello_key(NCRYPT_PROV_HANDLE provider, PCWSTR keyName, PCWSTR pinMessage)
    {
        return create_or_open_hello_key(provider, keyName, pinMessage, false);
    }

    inline wil::unique_ncrypt_key open_hello_key(NCRYPT_PROV_HANDLE provider, PCWSTR keyName, PCWSTR pinMessage)
    {
        return create_or_open_hello_key(provider, keyName, pinMessage, true).first;
    }

    inline void prompt_user_to_finalize_hello_key(NCRYPT_KEY_HANDLE key, NCRYPT_NGC_CACHE_CONFIG cacheConfig, bool promptForUnlock)
    {
        if (FAILED_LOG(NCryptSetProperty(key, NCRYPT_NGC_CACHE_TYPE_PROPERTY, reinterpret_cast<uint8_t*>(&cacheConfig.cacheType), sizeof(cacheConfig.cacheType), 0)))
        {
            // If we're in this failure case, SetProperty probably just failed because we already
            // created the key and finalized (it so we can no longer set properties on it.)
            //
            // This will happen if user makes a Hello key, but then uses it to secure 2 (or more)
            // of their encryption keys.
            return;
        }

        if (cacheConfig.cacheTimeout != 0)
        {
            THROW_IF_FAILED(NCryptSetProperty(
                key,
                NCRYPT_NGC_CACHE_TIMEOUT_PROPERTY,
                reinterpret_cast<uint8_t*>(&cacheConfig.cacheTimeout),
                sizeof(cacheConfig.cacheTimeout),
                0));
        }

        if (cacheConfig.cacheCount != 0)
        {
            THROW_IF_FAILED(NCryptSetProperty(key, NCRYPT_NGC_CACHE_COUNT_PROPERTY, reinterpret_cast<uint8_t*>(&cacheConfig.cacheCount), sizeof(cacheConfig.cacheCount), 0));
        }

        // This prompts hello dialog for user to auth (unless skipped by cache policy)
        THROW_IF_FAILED(NCryptFinalizeKey(key, promptForUnlock ? NULL : NCRYPT_SILENT_FLAG));
    }

    std::unique_ptr<std::vector<uint8_t>> send_request_to_ngc(DWORD capacity, NCRYPT_KEY_HANDLE helloKey, const veil::any::args::data_blob& request, bool promptForUnlock)
    {
        constexpr auto NCRYPT_NGC_AUTHENTICATED_REQ_RESP_FLAG = 0x80000000; // #define NCRYPT_NGC_AUTHENTICATED_REQ_RESP_FLAG 0x80000000

        auto response = std::make_unique<std::vector<uint8_t>>(capacity);

        DWORD responseSize = 0;
        DWORD flags = NCRYPT_NGC_AUTHENTICATED_REQ_RESP_FLAG;

        if (!promptForUnlock)
        {
            flags |= NCRYPT_SILENT_FLAG;
        }

        HRESULT hr = NCryptEncrypt(
            helloKey,
            static_cast<PBYTE>(request.data),
            gsl::narrow_cast<DWORD>(request.size),
            nullptr,
            static_cast<PBYTE>(response->data()),
            gsl::narrow_cast<DWORD>(capacity),
            &responseSize,
            flags);
        response->resize(responseSize);

        if (response->data() == nullptr && capacity == 0 && hr == S_OK && response->size() > 0)
        {
            THROW_HR(NTE_BUFFER_TOO_SMALL);
        }

        THROW_IF_FAILED(hr);
        return response;
    }
}

namespace simplified
{
    static void hellokeys_create_or_open_hello_key(veil::any::implementation::args::hellokeys_create_or_open_hello_key* data)
    {
        auto helloProvider = veil::vtl0::implementation::hello::open_provider();
        auto pinMessage = data->pinMessage;

        if (data->openOnly)
        {
            auto helloSecureSessionKey = veil::vtl0::implementation::hello::open_hello_key(helloProvider.get(), data->helloKeyName, pinMessage);
            data->helloKeyHandle = helloSecureSessionKey.release();
            data->createdKey = false;
        }
        else
        {
            auto [helloSecureSessionKey, createdKey] = veil::vtl0::implementation::hello::create_hello_key(helloProvider.get(), data->helloKeyName, pinMessage);
            data->helloKeyHandle = helloSecureSessionKey.release();
            data->createdKey = createdKey;
        }
    }

    static void hellokeys_get_challenge(veil::any::implementation::args::hellokeys_get_challenge* data)
    {
        DWORD challengeSize {};
        THROW_IF_FAILED(NCryptGetProperty(data->helloKeyHandle, NCRYPT_NGC_SESSION_CHALLENGE_PROPERTY, nullptr, 0, &challengeSize, 0));

        std::vector<uint8_t> challenge(challengeSize);
        THROW_IF_FAILED(NCryptGetProperty(data->helloKeyHandle, NCRYPT_NGC_SESSION_CHALLENGE_PROPERTY, challenge.data(), challengeSize, &challengeSize, 0));

        auto pChallenge = new std::vector<uint8_t>(challengeSize);
        challenge.swap(*pChallenge);
        data->challenge = pChallenge;
    }

    static void hellokeys_send_attestation_report(veil::any::implementation::args::hellokeys_send_attestation_report* data)
    {
        THROW_IF_FAILED(NCryptSetProperty(
            data->helloKeyHandle,
            NCRYPT_NGC_CLIENT_ATTESTATION_PROPERTY,
            (PUCHAR)data->report.data,
            static_cast<UINT32>(data->report.size),
            0));
    }

    static void hellokeys_finalize_key(veil::any::implementation::args::hellokeys_finalize_key* data)
    {
        veil::vtl0::implementation::hello::prompt_user_to_finalize_hello_key(data->helloKeyHandle, data->cacheConfig, data->promptForUnlock);
    }


    static void hellokeys_send_ngc_request(veil::any::implementation::args::hellokeys_send_ngc_request* data)
    {
        constexpr auto c_getIsSecureIdOwnerIdResponseSize = 0x11;
        constexpr auto c_getCacheConfigResponseSize = 0x1C;
        constexpr auto c_exportPublicKeyResponseSize = 0x100;
        constexpr auto c_deriveSharedSecretRequestSize = 0x280;

        auto largerSize = veil::any::math_max(c_deriveSharedSecretRequestSize, c_exportPublicKeyResponseSize);

        auto send = [&](int index, DWORD capacity)
        {
            auto response = veil::vtl0::implementation::hello::send_request_to_ngc(capacity, data->helloKeyHandle, data->requests[index], data->promptForUnlock);
            data->responses[index].data = response->data();
            data->responses[index].size = response->size();
            response.release();
        };
        send(0, c_getIsSecureIdOwnerIdResponseSize);
        send(1, c_getCacheConfigResponseSize);
        send(2, largerSize);
    }
}

namespace veil::vtl0::implementation::callbacks
{
    VEIL_ABI_FUNCTION_SIMPLIFIED(hellokeys_create_or_open_hello_key)

    void* hellokeys_close_handle_vtl1_ncrypt_key(void* args) noexcept
    {
        auto size = reinterpret_cast<size_t>(args);
        auto buffer = ::malloc(size);
        return buffer;
    }

    VEIL_ABI_FUNCTION_SIMPLIFIED(hellokeys_get_challenge)
    VEIL_ABI_FUNCTION_SIMPLIFIED(hellokeys_send_attestation_report)
    VEIL_ABI_FUNCTION_SIMPLIFIED(hellokeys_finalize_key)
    VEIL_ABI_FUNCTION_SIMPLIFIED(hellokeys_send_ngc_request)
}
