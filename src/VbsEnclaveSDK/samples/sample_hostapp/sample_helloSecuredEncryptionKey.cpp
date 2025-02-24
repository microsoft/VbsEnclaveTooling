// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "pch.h"

#include <filesystem>
#include <format>
#include <fstream>
#include <span>

#include <sddl.h>

#include <enclave_api.vtl0.h>

#include <sample_arguments.any.h>

#include <sample_utils.h>

std::wstring FormatUserHelloKeyName(PCWSTR name)
{
    static constexpr wchar_t c_formatString[] = L"//{}//{}";
    wil::unique_hlocal_string userSidString;
    THROW_IF_WIN32_BOOL_FALSE(ConvertSidToStringSid(wil::get_token_information<TOKEN_USER>()->User.Sid, &userSidString));

    return std::format(c_formatString, userSidString.get(), name);
}

namespace Samples::HelloSecuredEncryptionKey
{
    void main()
    {
        std::wcout << L"Running sample: Hello-secured encryption key..." << std::endl;

        // Create app+user enclave identity
        auto ownerId = veil::vtl0::appmodel::owner_id();

        // Load enclave
        auto flags = ENCLAVE_VBS_FLAG_DEBUG;

        auto enclave = veil::vtl0::enclave::create(ENCLAVE_TYPE_VBS, ownerId, flags, veil::vtl0::enclave::megabytes(512));
        veil::vtl0::enclave::load_image(enclave.get(), L"sample_enclave.dll");
        veil::vtl0::enclave::initialize(enclave.get(), 1);

        // Register framework callbacks
        veil::vtl0::enclave_api::register_callbacks(enclave.get());

        constexpr PCWSTR keyMoniker = L"MyHelloKey-001";

        // File with hello-secured encryption key bytes
        auto keyFilePath = std::filesystem::path(LR"(c:\t\secured_keys)") / keyMoniker;

        const bool createFlow = !std::filesystem::exists(keyFilePath);

        //
        // [Create flow]
        // 
        //  Generate hello-secured key in enclave, then save (encrypted) key bytes to disk
        //
        if (createFlow)
        {
            // Name of a hello key that will be the "root" of our encryption ancestry
            auto helloKeyName = FormatUserHelloKeyName(keyMoniker);

            // Call into enclave
            sample::args::RunHelloSecuredEncryptionKeyExample_CreateEncryptionKey data;
            data.helloKeyName = helloKeyName;
            THROW_IF_FAILED(veil::vtl0::enclave::call_enclave(enclave.get(), "RunHelloSecuredEncryptionKeyExample_CreateEncryptionKey", data));

            // We now have our encryption key's bytes, which are "hello-secured" and sealed!
            //
            //  Meaning of "hello-secured" and sealed:
            //      1. Our encryption key is encrypted by a 'KEK' key (*not persisted anywhere*) that
            //          can only be re-materialized my NGC if user enters their Hello PIN or biometric auth
            //          ('proof of presence').
            //
            //      2. Our encryption key is sealed by the enclave (i.e. can only be unsealed
            //          by the sealing-enclave or an enclave signed with compatible signature).
            auto securedEncryptionKeyBytes = std::span<uint8_t>(reinterpret_cast<uint8_t*>(data.securedEncryptionKeyBytes.data), data.securedEncryptionKeyBytes.size);

            // Save to disk
            SaveBinaryData(keyFilePath.string(), securedEncryptionKeyBytes);
        }
        //
        // [Load flow]
        // 
        //  Retrieve (encrypted) key bytes from disk, then pass into enclave and reconstitute
        //
        else
        {
            for (int i = 0; i < 2; i++)
            {
                auto securedEncryptionKeyBytes = LoadBinaryData(keyFilePath.string());

                // Call into enclave
                sample::args::RunHelloSecuredEncryptionKeyExample_LoadEncryptionKey data;
                data.securedEncryptionKeyBytes.data = securedEncryptionKeyBytes.data();
                data.securedEncryptionKeyBytes.size = securedEncryptionKeyBytes.size();
                THROW_IF_FAILED(veil::vtl0::enclave::call_enclave(enclave.get(), "RunHelloSecuredEncryptionKeyExample_LoadEncryptionKey", data));

                if (data.needsReseal)
                {
                    // Save resealed secured encryption key to disk
                    auto resealedEncryptionKeyBytes = std::span<uint8_t>(reinterpret_cast<uint8_t*>(data.resealedEncryptionKeyBytes.data), data.resealedEncryptionKeyBytes.size);
                    SaveBinaryData(keyFilePath.string(), resealedEncryptionKeyBytes);

                    // ..loop and retry
                }
                else
                {
                    break;
                }
            }
        }


        std::wcout << L"Finished sample: Hello-secured encryption key..." << std::endl;
    }

}
