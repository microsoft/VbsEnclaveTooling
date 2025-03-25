// Copyright (c) Microsoft Corporation.
//

#include "pch.h"

#include <array>
#include <stdexcept>

#include <veil.any.h>

#include <enclave_interface.vtl1.h>
#include <export_helpers.vtl1.h>
#include <hello.vtl1.h>
#include <taskpool.vtl1.h>
#include <vtl0_functions.vtl1.h>

#include "sample_arguments.any.h"

namespace RunTaskpoolExamples
{
    void Test_Dont_WaitForAllTasksToFinish(_In_ sample::args::RunTaskpoolExample* data)
    {
        using namespace veil::vtl1::vtl0_functions;

        debug_print(L"Creating taskpool with '%d' threads...", data->threadCount);

        auto tasks = std::vector<veil::vtl1::future<void>>();

        std::atomic<bool> ranLastTask = false;

        // taskpool
        {
            auto taskpool = veil::vtl1::taskpool(data->threadCount, false);

            // Use up all the threads
            for (uint32_t i = 0; i < data->threadCount; i++)
            {
                auto task = taskpool.queue_task([=] ()
                {
                    debug_print(L"hello from task: %d", i);
                    veil::vtl1::sleep(500);
                });
                tasks.push_back(std::move(task));
            }

            auto task = taskpool.queue_task([&ranLastTask] ()
            {
                ranLastTask = true;
                debug_print(L"...you SHOULD NOT see this message...");
            });

            // Detach the future from the shared state so its destructor doesn't block on waiting forever (it's never scheduled)
            task.detach();

            debug_print(L"Waiting for taskpool to destruct...");
        }

        if (ranLastTask)
        {
            debug_print(L"ERROR: Taskpool destructed after all tasks finished.");
        }
        else
        {
            debug_print(L"SUCCESS: Taskpool destructed before all tasks finished.");
        }

        // We must detach all unfinished tasks that still exist after the lifetime of the taskpool.
        // These tasks were never queued, so their destructors will block forever.
        for (auto& task : tasks)
        {
            task.detach();
        }
    }

    void Test_Do_WaitForAllTasksToFinish(_In_ sample::args::RunTaskpoolExample* data)
    {
        using namespace veil::vtl1::vtl0_functions;

        debug_print(L"Creating taskpool with '%d' threads...", data->threadCount);

        auto tasks = std::vector<veil::vtl1::future<void>>();

        std::atomic<bool> ranLastTask = false;

        // taskpool
        {
            auto taskpool = veil::vtl1::taskpool(data->threadCount, true);

            // Use up all the threads
            for (uint32_t i = 0; i < data->threadCount; i++)
            {
                auto task = taskpool.queue_task([=] ()
                {
                    debug_print(L"hello from task: %d", i);
                    veil::vtl1::sleep(500);
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
    }

    void Test_Cancellation(_In_ sample::args::RunTaskpoolExample* data)
    {
        using namespace veil::vtl1::vtl0_functions;

        debug_print(L"Creating taskpool with '%d' threads...", data->threadCount);

        auto tasks = std::vector<veil::vtl1::future<void>>();

        std::atomic<bool> ranLastTask = false;

        // taskpool
        {
            auto taskpool = veil::vtl1::taskpool(data->threadCount, true);

            // Use up all the threads
            for (uint32_t i = 0; i < data->threadCount; i++)
            {
                auto task = taskpool.queue_task([=] ()
                {
                    debug_print(L"hello from task: %d", i);
                    veil::vtl1::sleep(500);
                });
                task.detach();
            }

            auto task = taskpool.queue_task([&ranLastTask] ()
            {
                ranLastTask = true;
                debug_print(L"...you SHOULD NOT see this message...");
            });
            task.detach();

            taskpool.cancel_queued_tasks();

            debug_print(L"Waiting for taskpool to destruct...");
        }

        if (ranLastTask)
        {
            debug_print(L"ERROR: Taskpool destructed after all tasks finished.");
        }
        else
        {
            debug_print(L"SUCCESS: Taskpool destructed before all tasks finished.");
        }
    }

    void UsageExample(_In_ sample::args::RunTaskpoolExample* data)
    {
        using namespace veil::vtl1::vtl0_functions;

        debug_print(L"Creating taskpool with '%d' threads...", data->threadCount);

        auto taskpool = veil::vtl1::taskpool(data->threadCount, true);

        auto task_1 = taskpool.queue_task([=] ()
        {
            veil::vtl1::sleep(500);
            debug_print(L"hello from task 1");
        });

        auto task_2 = taskpool.queue_task([=] ()
        {
            veil::vtl1::sleep(500);
            debug_print(L"hello from task 2");
        });

        struct complex_struct
        {
            std::wstring contents;
        };

        auto a_complex_task = taskpool.queue_task([=] ()
        {
            veil::vtl1::sleep(500);
            debug_print(L"hello from complex task");
            return complex_struct {L"this is a complex struct!"};
        });

        debug_print(L"Waiting for tasks...");

        task_1.get();
        task_2.get();
        auto a_complex_struct = a_complex_task.get();

        debug_print(L"complex task returned a complex struct: %ls", a_complex_struct.contents.c_str());

        debug_print(L"Waiting for taskpool to destruct...");
    }

    void UsageExceptionExample(_In_ sample::args::RunTaskpoolExample* data)
    {
        using namespace veil::vtl1::vtl0_functions;

        debug_print(L"Creating taskpool with '%d' threads...", data->threadCount);

        auto taskpool = veil::vtl1::taskpool(data->threadCount, true);

        auto task1 = taskpool.queue_task([=] ()
        {
            volatile int x = 5;
            if (x == 5)
            {
                throw std::runtime_error("task1 threw this exception");
            }
        });

        auto task2 = taskpool.queue_task([=] ()
        {
            volatile int x = 5;
            if (x == 5)
            {
                throw std::runtime_error("task2 threw this exception");
            }
            return 1234;
        });

        try
        {
            task1.get();
        }
        catch (std::runtime_error e)
        {
            debug_print("Caught exception from running task: %s", e.what());
        }

        try
        {
            task2.get();
        }
        catch (std::runtime_error e)
        {
            debug_print("Caught exception from running task: %s", e.what());
        }

        debug_print(L"Waiting for taskpool to destruct...");
    }
}

//
// Taskpool
//
void RunTaskpoolExampleImpl(_In_ sample::args::RunTaskpoolExample* data)
{
    using namespace veil::vtl1::vtl0_functions;

    debug_print(L"TEST: Taskpool destruction, don't wait for all tasks to finish");
    RunTaskpoolExamples::Test_Dont_WaitForAllTasksToFinish(data);
    debug_print(L"");

    debug_print(L"TEST: Taskpool destruction, wait for all tasks to finish");
    RunTaskpoolExamples::Test_Do_WaitForAllTasksToFinish(data);
    debug_print(L"");

    debug_print(L"TEST: Taskpool cancellation");
    RunTaskpoolExamples::Test_Cancellation(data);
    debug_print(L"");

    debug_print(L"USAGE");
    RunTaskpoolExamples::UsageExample(data);
    debug_print(L"");

    debug_print(L"USAGE EXCEPTIONS");
    RunTaskpoolExamples::UsageExceptionExample(data);
    debug_print(L"");
}

ENCLAVE_FUNCTION RunTaskpoolExample(_In_ PVOID pv) noexcept try
{
    auto data = reinterpret_cast<sample::args::RunTaskpoolExample*>(pv);
    RunTaskpoolExampleImpl(data);
    return nullptr;
}
catch (...)
{
    LOG_CAUGHT_EXCEPTION();
    RETURN_HR_AS_PVOID(wil::ResultFromCaughtException());
}

//
// Hello-secured encryption key
//
void RunHelloSecuredEncryptionKeyExample_CreateEncryptionKeyImpl(_In_ sample::args::RunHelloSecuredEncryptionKeyExample_CreateEncryptionKey* data)
{
    using namespace veil::vtl1::vtl0_functions;
    
    const bool requireEnclaveOwnerIdMatchesHelloContainerSecureId = false;
    veil::any::telemetry::activity enclaveLog(data->activityLevel);
    enclaveLog.AddLog(L"[Enclave] In RunHelloSecuredEncryptionKeyExample_CreateEncryptionKeyImpl", veil::any::telemetry::eventLevel::EVENT_LEVEL_CRITICAL);

    debug_print("");
    debug_print(L"[Create flow]");
    debug_print("");
    enclaveLog.AddLog(L"[Enclave] Create flow", veil::any::telemetry::eventLevel::EVENT_LEVEL_VERBOSE);
    
    // Create a hello key for the root of our Hello-secured encryption key
    debug_print(L"1. Creating a 'Hello' key: %ws", data->helloKeyName.c_str());
    enclaveLog.AddLog(L"[Enclave] Creating a 'Hello' key: " + data->helloKeyName, veil::any::telemetry::eventLevel::EVENT_LEVEL_INFO);
    auto [helloKey, createdKey] = veil::vtl1::hello::create_or_open_hello_key(data->helloKeyName, L"Let's secure the encryption key with this Hello key!");
    debug_print("");

    // Generate our encryption key
    debug_print(L"2. Generating our encryption key");
    enclaveLog.AddLog(L"[Enclave] Generating our encryption key", veil::any::telemetry::eventLevel::EVENT_LEVEL_INFO);
    auto encryptionKeyBytes = veil::vtl1::crypto::generate_symmetric_key_bytes();
    debug_print(L" ...CHECKPOINT: encryption key byte count: %d", encryptionKeyBytes.size());
    std::wstring logSizeStr = std::to_wstring(encryptionKeyBytes.size());
    enclaveLog.AddLog(L"[Enclave] Encryption key byte count: " + logSizeStr, veil::any::telemetry::eventLevel::EVENT_LEVEL_CRITICAL);
    debug_print("");

    // Arbitrary metadata to encode in the final secured serialized key material blob saved on disk
    std::wstring customData = L"usage=for_decryption";

    // Secure our encryption key with Hello
    debug_print(L"3. Securing our encryption key with Hello");
    enclaveLog.AddLog(L"[Enclave] Securing our encryption key with Hello", veil::any::telemetry::eventLevel::EVENT_LEVEL_INFO);
    auto serializedHelloSecuredKey = veil::vtl1::hello::conceal_encryption_key_with_hello(
        helloKey.get(),
        data->helloKeyName,
        STANDARD_HELLO_KEY_CACHE_CONFIG,
        encryptionKeyBytes,
        veil::vtl1::as_data_span(customData),
        requireEnclaveOwnerIdMatchesHelloContainerSecureId);
    debug_print(L" ...CHECKPOINT: secured encryption key material byte count: %d", serializedHelloSecuredKey.size());
    logSizeStr = std::to_wstring(serializedHelloSecuredKey.size());
    enclaveLog.AddLog(L"[Enclave] Secured encryption key material byte count: " + logSizeStr, veil::any::telemetry::eventLevel::EVENT_LEVEL_CRITICAL);
    debug_print("");
    
    // Seal it so only our enclave may open it
    debug_print(L"4. Sealing the serialized key material for our enclave only");
    enclaveLog.AddLog(L"[Enclave] Sealing the serialized key material for our enclave only", veil::any::telemetry::eventLevel::EVENT_LEVEL_INFO);
    auto sealedKeyMaterial = veil::vtl1::crypto::seal_data(serializedHelloSecuredKey, ENCLAVE_IDENTITY_POLICY_SEAL_SAME_IMAGE, ENCLAVE_RUNTIME_POLICY_ALLOW_FULL_DEBUG);
    debug_print(L" ...CHECKPOINT: sealed key material byte count: %d", sealedKeyMaterial.size());
    logSizeStr = std::to_wstring(sealedKeyMaterial.size());
    enclaveLog.AddLog(L"[Enclave] Sealed key material byte count: " + logSizeStr, veil::any::telemetry::eventLevel::EVENT_LEVEL_CRITICAL);
    debug_print("");

    // Erase our plain-text encryption key, (not necessary, but being explicit that we do not need this data anymore)
    encryptionKeyBytes.fill(0);

    // Return the secured encryption key to vtl0 host caller...
    auto buffer_vtl0 = veil::vtl1::memory::copy_to_vtl0_data_blob(&data->securedEncryptionKeyBytes, sealedKeyMaterial);
    buffer_vtl0.release();

    // Return the logs to vtl0 host caller...
    std::vector<uint8_t> logBytes = enclaveLog.WstringToBytes();
    auto buffer1_vtl0 = veil::vtl1::memory::copy_to_vtl0_data_blob(&data->enclaveLog, logBytes);
    buffer1_vtl0.release();
}

ENCLAVE_FUNCTION RunHelloSecuredEncryptionKeyExample_CreateEncryptionKey(_In_ PVOID pv) noexcept try
{
    auto data = reinterpret_cast<sample::args::RunHelloSecuredEncryptionKeyExample_CreateEncryptionKey*>(pv);
    RunHelloSecuredEncryptionKeyExample_CreateEncryptionKeyImpl(data);
    return nullptr;
}
catch (...)
{
    using namespace veil::vtl1::vtl0_functions;
    auto error = veil::vtl1::implementation::export_helpers::get_back_thread_enclave_error(GetCurrentThreadId());
    debug_print(error->wmessage);

    LOG_CAUGHT_EXCEPTION();
    RETURN_HR_AS_PVOID(wil::ResultFromCaughtException());
}

bool RunHelloSecuredEncryptionKeyExample_LoadEncryptionKeyImpl(_In_ sample::args::RunHelloSecuredEncryptionKeyExample_LoadEncryptionKey* data)
{
    using namespace veil::vtl1::vtl0_functions;
    const bool requireEnclaveOwnerIdMatchesHelloContainerSecureId = false;

    veil::any::telemetry::activity enclaveLog(data->activityLevel);
    enclaveLog.AddLog(L"[Enclave] In RunHelloSecuredEncryptionKeyExample_LoadEncryptionKeyImpl", veil::any::telemetry::eventLevel::EVENT_LEVEL_CRITICAL);
    
    debug_print("");
    debug_print(L"[Load flow]");
    debug_print("");

    debug_print(L"1. Unsealing our encryption key (only our enclave can succeed this operation)");
    auto [unsealedBytes, unsealingFlags] = veil::vtl1::crypto::unseal_data(data->securedEncryptionKeyBytes);
    debug_print(L" ...CHECKPOINT: unsealed byte count: = %d", unsealedBytes.size());
    debug_print("");
    
    // Arbitrary metadata that must match what's encoded in the serialized key blob
    std::wstring expectedCustomData = L"usage=for_decryption";

    // Decrypt the encryption key
    debug_print(L"2. Unsecuring our encryption key with Hello");
    auto encryptionKey = veil::vtl1::hello::reveal_encryption_key_with_hello(unsealedBytes, veil::vtl1::as_data_span(expectedCustomData), requireEnclaveOwnerIdMatchesHelloContainerSecureId);
    debug_print(L" ...CHECKPOINT: encryption key handle: = %d", encryptionKey.get());
    debug_print("");

    if (data->isToBeEncrypted)
    {
        //
        // Now let's encrypt the input data with our encryption key
        //

        // Encrypting the user input data
        auto const SOME_PLAIN_TEXT = data->dataToEncrypt.c_str();

        // Let's encrypt the input text
        debug_print(L"3. Encrypting input text.");
        auto [encryptedText, tag] = veil::vtl1::crypto::encrypt(encryptionKey.get(), veil::vtl1::as_data_span(SOME_PLAIN_TEXT), veil::vtl1::crypto::zero_nonce);
        debug_print(L" ...CHECKPOINT: encrypted text's byte count: = %d", encryptedText.size());
        debug_print("");

        // Return the encrypted input to vtl0 host caller...
        auto buffer_vtl0 = veil::vtl1::memory::copy_to_vtl0_data_blob(&data->encryptedInputBytes, encryptedText);
        buffer_vtl0.release();

        auto buffer1_vtl0 = veil::vtl1::memory::copy_to_vtl0_data_blob(&data->tag, tag);
        buffer1_vtl0.release();
    }
    else
    {
        // Let's decrypt the stored encrypted input
        debug_print(L"4. Decrypting text...");
        auto decryptedText = veil::vtl1::crypto::decrypt(encryptionKey.get(), data->encryptedInputBytes, veil::vtl1::crypto::zero_nonce, data->tag);
        std::wstring decryptedString = veil::vtl1::to_wstring(decryptedText);
        debug_print(L" ...CHECKPOINT: decrypted text: = %ws", decryptedString.c_str());
        debug_print("");

        // Return the decrypted input to vtl0 host caller...
        auto buffer_vtl0 = veil::vtl1::memory::copy_to_vtl0_data_blob(&data->decryptedInputBytes, decryptedText);
        buffer_vtl0.release();
    }

    // Return the logs to vtl0 host caller...
    std::vector<uint8_t> logBytes = enclaveLog.WstringToBytes();
    auto buffer1_vtl0 = veil::vtl1::memory::copy_to_vtl0_data_blob(&data->enclaveLog, logBytes);
    buffer1_vtl0.release();

    return true;
}

ENCLAVE_FUNCTION RunHelloSecuredEncryptionKeyExample_LoadEncryptionKey(_In_ PVOID pv) noexcept try
{
    auto data = reinterpret_cast<sample::args::RunHelloSecuredEncryptionKeyExample_LoadEncryptionKey*>(pv);
    if (!RunHelloSecuredEncryptionKeyExample_LoadEncryptionKeyImpl(data)) 
    { }
    return nullptr;
}
catch (...)
{
    using namespace veil::vtl1::vtl0_functions;
    auto error = veil::vtl1::implementation::export_helpers::get_back_thread_enclave_error(GetCurrentThreadId());
    debug_print(error->wmessage);

    LOG_CAUGHT_EXCEPTION();
    RETURN_HR_AS_PVOID(wil::ResultFromCaughtException());
}
