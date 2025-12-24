// Copyright (c) Microsoft Corporation.
//

#include <pch.h>
#include "threaded_encryption.h"
#include "basic_encryption.h" // For RunEncryptionKeyExample_LoadEncryptionKeyImpl
#include "..\Common\globals.h"

#include <veil\enclave\taskpool.vtl1.h>
#include <veil\enclave\vtl0_functions.vtl1.h>
#include <VbsEnclave\Enclave\Implementation\Types.h>

#include <vector>
#include <atomic>

using namespace veil::vtl1::vtl0_functions;

//
// Load encryption key and encrypt data using threadpool
//
HRESULT VbsEnclave::Trusted::Implementation::RunEncryptionKeyExample_LoadEncryptionKeyAndEncryptThreadpool(
    _In_ const std::vector<std::uint8_t>& securedEncryptionKeyBytes,
    _In_ const std::wstring& dataToEncrypt1,
    _In_ const std::wstring& dataToEncrypt2,
    _In_ const std::uint32_t activity_level,
    _In_ const std::wstring& logFilePath,
    _Out_ std::vector<std::uint8_t>& resealedEncryptionKeyBytes,
    _Out_ std::vector<std::uint8_t>& encryptedInputBytes1,
    _Out_ std::vector<std::uint8_t>& encryptedInputBytes2,
    _Out_ std::vector<std::uint8_t>& tag1,
    _Out_ std::vector<std::uint8_t>& tag2)
{
    auto threadCount = 2u;

    debug_print(L"Creating taskpool with '%d' threads for encryption...", threadCount);

    auto tasks = std::vector<veil::vtl1::future<void>>();

    std::atomic<bool> ranLastTask = false;

    // taskpool
    {
        auto taskpool = veil::vtl1::taskpool(threadCount, true);

        // Use up all the threads for encryption
        for (uint32_t i = 0; i < threadCount; i++)
        {
            auto task = taskpool.queue_task([&, i=i] ()
            {
                auto logPrefix = L"[THREAD " + std::to_wstring(i) + L"]";
                auto helloStr = logPrefix + L" Hello from encryption task.";
                debug_print(helloStr.c_str());

                auto a = std::vector<uint8_t> {};
                auto b = std::vector<uint8_t> {};
                auto c = std::vector<uint8_t> {};
                auto d = std::wstring {};
                if (FAILED(RunEncryptionKeyExample_LoadEncryptionKeyImpl(
                        securedEncryptionKeyBytes,
                        (i == 0) ? dataToEncrypt1 : dataToEncrypt2,
                        true, // isToBeEncrypted = true for encryption
                        activity_level,
                        logFilePath,
                        a,
                        b,
                        c,
                        d,
                        true /* called from threadPool */,
                        logPrefix,
                        (i == 0) ? &encryptedInputBytes1 : &encryptedInputBytes2,
                        (i == 0) ? &tag1 : &tag2)))
                {}
            });
            tasks.push_back(std::move(task));
        }

        auto task = taskpool.queue_task([&ranLastTask] ()
        {
            ranLastTask = true;
            debug_print(L"...you SHOULD see this message...");
        });
        tasks.push_back(std::move(task));

        debug_print(L"Waiting for taskpool to destruct...");
    }

    if (!ranLastTask)
    {
        debug_print(L"ERROR: Taskpool destructed before all tasks finished.");
    }
    else
    {
        debug_print(L"SUCCESS: Taskpool destructed after all tasks finished.");
    }

    return S_OK;
}

//
// Load encryption key and decrypt data using threadpool
//
HRESULT VbsEnclave::Trusted::Implementation::RunEncryptionKeyExample_LoadEncryptionKeyAndDecryptThreadpool(
    _In_ const std::vector<std::uint8_t>& securedEncryptionKeyBytes,
    _In_ const std::uint32_t activity_level,
    _In_ const std::wstring& logFilePath,
    _In_ const std::vector<std::uint8_t>& encryptedInputBytes1,
    _In_ const std::vector<std::uint8_t>& encryptedInputBytes2,
    _In_ const std::vector<std::uint8_t>& tag1,
    _In_ const std::vector<std::uint8_t>& tag2,
    _Out_ std::vector<std::uint8_t>& resealedEncryptionKeyBytes,
    _Out_ std::wstring& decryptedInputBytes1,
    _Out_ std::wstring& decryptedInputBytes2)
{
    auto threadCount = 2u;

    debug_print(L"Creating taskpool with '%d' threads for decryption...", threadCount);

    auto tasks = std::vector<veil::vtl1::future<void>>();

    std::atomic<bool> ranLastTask = false;

    // Create local copies for thread-safe access
    std::vector<std::uint8_t> localEncryptedInputBytes1 = encryptedInputBytes1;
    std::vector<std::uint8_t> localEncryptedInputBytes2 = encryptedInputBytes2;
    std::vector<std::uint8_t> localTag1 = tag1;
    std::vector<std::uint8_t> localTag2 = tag2;

    // taskpool
    {
        auto taskpool = veil::vtl1::taskpool(threadCount, true);

        // Use up all the threads for decryption
        for (uint32_t i = 0; i < threadCount; i++)
        {
            auto task = taskpool.queue_task([&, i=i] ()
            {
                debug_print(L"hello from decryption task: %d", i);

                auto a = std::vector<uint8_t> {};
                auto b = std::wstring {};
                if (FAILED(RunEncryptionKeyExample_LoadEncryptionKeyImpl(
                    securedEncryptionKeyBytes,
                    {}, // dataToEncrypt unused in decryption
                    false, // isToBeEncrypted = false for decryption
                    activity_level,
                    logFilePath,
                    a,
                    (i == 0) ? localEncryptedInputBytes1 : localEncryptedInputBytes2,
                    (i == 0) ? localTag1 : localTag2,
                    b,
                    true /* called from threadPool */,
                    L"[THREAD " + std::to_wstring(i) + L"]",
                    nullptr,
                    nullptr,
                    (i == 0) ? &decryptedInputBytes1 : &decryptedInputBytes2)))
                {
                }
            });
            tasks.push_back(std::move(task));
        }

        auto task = taskpool.queue_task([&ranLastTask] ()
        {
            ranLastTask = true;
            debug_print(L"...you SHOULD see this message...");
        });
        tasks.push_back(std::move(task));

        debug_print(L"Waiting for taskpool to destruct...");
    }

    if (!ranLastTask)
    {
        debug_print(L"ERROR: Taskpool destructed before all tasks finished.");
    }
    else
    {
        debug_print(L"SUCCESS: Taskpool destructed after all tasks finished.");
    }

    return S_OK;
}
