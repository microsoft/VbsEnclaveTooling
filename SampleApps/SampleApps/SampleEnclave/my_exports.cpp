// Copyright (c) Microsoft Corporation.
//

#include "pch.h"

#include <array>
#include <stdexcept>

#include <veil\enclave\crypto.vtl1.h>
#include <veil\enclave\logger.vtl1.h>
#include <veil\enclave\taskpool.vtl1.h>
#include <veil\enclave\userboundkey.vtl1.h>
#include <veil\enclave\vtl0_functions.vtl1.h>
#include <VbsEnclave\Enclave\Implementation\Trusted.h>
#include <VbsEnclave\Enclave\Implementation\Types.h>

// Store the actual key object, not just the handle
wil::unique_bcrypt_key g_encryptionKey;

// SRW lock to protect access to g_encryptionKey (enclave-compatible)
wil::srwlock g_encryptionKeyLock;

// Store the asymmetric private key object for signing
wil::unique_bcrypt_key g_asymmetricPrivateKey;

// SRW lock to protect access to g_asymmetricPrivateKey (enclave-compatible)
wil::srwlock g_asymmetricPrivateKeyLock;

// Global runtime policy for enclave operations
// 
// ENCLAVE_RUNTIME_POLICY_ALLOW_FULL_DEBUG:
//   - **DEBUG ONLY** - Allows debugger to attach and inspect enclave state
//   - **SECURITY WARNING**: Reduces isolation guarantees in debug builds
//   - Production builds should use 0 (no debug policy) for maximum security
#ifdef _DEBUG
    constexpr UINT32 g_runtimePolicy = ENCLAVE_RUNTIME_POLICY_ALLOW_FULL_DEBUG;
#else
    // Production: No debug policy - maximum security and isolation
    constexpr UINT32 g_runtimePolicy = 0;
#endif

bool IsUBKLoaded()
{
    // Thread-safe check if the key object is valid
    auto lock = g_encryptionKeyLock.lock_shared();
    return static_cast<bool>(g_encryptionKey);
}

// Helper function to safely get a copy of the key handle for use in crypto operations
// Returns nullptr if key is not loaded
BCRYPT_KEY_HANDLE GetEncryptionKeyHandle()
{
    auto lock = g_encryptionKeyLock.lock_shared();
    return g_encryptionKey.get();
}

// Helper function to safely set the encryption key
void SetEncryptionKey(wil::unique_bcrypt_key&& newKey)
{
    auto lock = g_encryptionKeyLock.lock_exclusive();
    g_encryptionKey = std::move(newKey);
}

// Check if asymmetric private key is loaded
bool IsAsymmetricPrivateKeyLoaded()
{
    // Thread-safe check if the asymmetric private key object is valid
    auto lock = g_asymmetricPrivateKeyLock.lock_shared();
    return static_cast<bool>(g_asymmetricPrivateKey);
}

// Helper function to safely get the asymmetric private key handle
// Returns nullptr if key is not loaded
BCRYPT_KEY_HANDLE GetAsymmetricPrivateKeyHandle()
{
    auto lock = g_asymmetricPrivateKeyLock.lock_shared();
    return g_asymmetricPrivateKey.get();
}

// Helper function to safely set the asymmetric private key
void SetAsymmetricPrivateKey(wil::unique_bcrypt_key&& newKey)
{
    auto lock = g_asymmetricPrivateKeyLock.lock_exclusive();
    g_asymmetricPrivateKey = std::move(newKey);
}

// VTL1 function to create secure cache configuration
// This ensures VTL0 has no influence over cache configuration values
veil::vtl1::userboundkey::keyCredentialCacheConfig CreateSecureKeyCredentialCacheConfig()
{
    using namespace veil::vtl1::vtl0_functions;
    
    veil::vtl1::userboundkey::keyCredentialCacheConfig secureConfig;
    
    // VTL1 sets secure cache configuration values
    // VTL0 cannot influence these security-critical settings
    secureConfig.cacheOption = 0; // NoCache - most secure option
    secureConfig.cacheTimeoutInSeconds = 0; // No timeout when not caching
    secureConfig.cacheUsageCount = 0; // No usage count when not caching

    debug_print(L"VTL1 created secure cache config - NoCache policy for maximum security");
    
    return secureConfig;
}

// Helper function to ensure user-bound key is loaded
// Handles initial load attempt and optional reseal if needed
static HRESULT EnsureUserBoundKeyLoaded(
    _In_ const std::wstring& helloKeyName,
    _In_ const std::wstring& pinMessage,
    _In_ const uintptr_t windowId,
    _In_ const std::vector<std::uint8_t>& securedEncryptionKeyBytes,
    _Inout_ bool& needsReseal,
    _Out_ std::vector<std::uint8_t>& resealedEncryptionKeyBytes)
{
    using namespace veil::vtl1::vtl0_functions;

    // Only load the user-bound key if it's not already loaded
    if (!IsUBKLoaded())
    {
        debug_print(L"UBK not loaded, loading user-bound key");

        // VTL1 creates secure cache configuration - VTL0 input is ignored
        auto secureConfig = CreateSecureKeyCredentialCacheConfig();

        debug_print(L"Created secure cache configuration in VTL1");

        std::vector<std::uint8_t> loadedKeyBytes;
        bool loadSucceeded = false;

        // First attempt to load the user-bound key
        try
        {
            loadedKeyBytes = veil::vtl1::userboundkey::load_user_bound_key(
                helloKeyName,
                secureConfig,
                pinMessage,
                windowId,
                securedEncryptionKeyBytes,
                needsReseal);
            loadSucceeded = true;
            debug_print(L"Successfully loaded user-bound key on first attempt");
        }
        catch (...)
        {
            debug_print(L"First load attempt failed, checking if reseal is needed");
            loadSucceeded = false;
        }

        // If load failed and reseal is needed, attempt reseal and retry
        if (!loadSucceeded && needsReseal)
        {
            debug_print(L"Attempting to reseal user-bound key");
      
            try
            {
                auto resealedBytes = veil::vtl1::userboundkey::reseal_user_bound_key(
                    securedEncryptionKeyBytes,
                    ENCLAVE_SEALING_IDENTITY_POLICY::ENCLAVE_IDENTITY_POLICY_SEAL_SAME_IMAGE,
                    g_runtimePolicy);

                debug_print(L"Reseal completed, attempting to load with resealed key");

                // Store resealed bytes in output parameter
                resealedEncryptionKeyBytes.assign(resealedBytes.begin(), resealedBytes.end());

                // Reset needsReseal for the retry
                needsReseal = false;

                // Retry loading with resealed bytes
                loadedKeyBytes = veil::vtl1::userboundkey::load_user_bound_key(
                    helloKeyName,
                    secureConfig,
                    pinMessage,
                    windowId,
                    resealedBytes,
                    needsReseal);

                loadSucceeded = true;
                debug_print(L"Successfully loaded user-bound key after reseal");
            }
            catch (...)
            {
                debug_print(L"Failed to reseal or load after reseal");
                throw;
            }
        }
        else if (!loadSucceeded)
        {
            debug_print(L"Load failed and reseal not needed or not indicated");
            throw; // Re-throw the original exception
        }

        // NOW we can create a symmetric key from the loaded raw key material
        auto newEncryptionKey = veil::vtl1::crypto::create_symmetric_key(loadedKeyBytes);
        SetEncryptionKey(std::move(newEncryptionKey));
        debug_print(L"Created symmetric key from loaded user-bound key material");
    }
    else
    {
        debug_print(L"UBK already loaded, using cached key");
    }

    return S_OK;
}

// Helper function to ensure asymmetric user-bound key (private key) is loaded
// Handles initial load attempt and optional reseal if needed
static HRESULT EnsureAsymmetricUserBoundKeyLoaded(
    _In_ const std::wstring& helloKeyName,
    _In_ const std::wstring& pinMessage,
    _In_ const uintptr_t windowId,
    _In_ const std::vector<std::uint8_t>& securedPrivateKeyBytes,
    _Inout_ bool& needsReseal,
    _Out_ std::vector<std::uint8_t>& resealedPrivateKeyBytes)
{
    using namespace veil::vtl1::vtl0_functions;

    // Only load the asymmetric private key if it's not already loaded
    if (!IsAsymmetricPrivateKeyLoaded())
    {
        debug_print(L"Asymmetric private key not loaded, loading user-bound key");

        // VTL1 creates secure cache configuration - VTL0 input is ignored
        auto secureConfig = CreateSecureKeyCredentialCacheConfig();

        debug_print(L"Created secure cache configuration in VTL1");

        std::vector<std::uint8_t> loadedKeyBytes;
        bool loadSucceeded = false;

        // First attempt to load the user-bound private key
        try
        {
            loadedKeyBytes = veil::vtl1::userboundkey::load_user_bound_key(
                helloKeyName,
                secureConfig,
                pinMessage,
                windowId,
                securedPrivateKeyBytes,
                needsReseal);
            loadSucceeded = true;
            debug_print(L"Successfully loaded user-bound private key on first attempt");
        }
        catch (...)
        {
            debug_print(L"First load attempt failed, checking if reseal is needed");
            loadSucceeded = false;
        }

        // If load failed and reseal is needed, attempt reseal and retry
        if (!loadSucceeded && needsReseal)
        {
            debug_print(L"Attempting to reseal user-bound private key");
      
            try
            {
                auto resealedBytes = veil::vtl1::userboundkey::reseal_user_bound_key(
                    securedPrivateKeyBytes,
                    ENCLAVE_SEALING_IDENTITY_POLICY::ENCLAVE_IDENTITY_POLICY_SEAL_SAME_IMAGE,
                    g_runtimePolicy);

                debug_print(L"Reseal completed, attempting to load with resealed key");

                // Store resealed bytes in output parameter
                resealedPrivateKeyBytes.assign(resealedBytes.begin(), resealedBytes.end());

                // Reset needsReseal for the retry
                needsReseal = false;

                // Retry loading with resealed bytes
                loadedKeyBytes = veil::vtl1::userboundkey::load_user_bound_key(
                    helloKeyName,
                    secureConfig,
                    pinMessage,
                    windowId,
                    resealedBytes,
                    needsReseal);

                loadSucceeded = true;
                debug_print(L"Successfully loaded user-bound private key after reseal");
            }
            catch (...)
            {
                debug_print(L"Failed to reseal or load after reseal");
                throw;
            }
        }
        else if (!loadSucceeded)
        {
            debug_print(L"Load failed and reseal not needed or not indicated");
            throw; // Re-throw the original exception
        }

        // NOW we can import the private key from the loaded raw key material
        auto newAsymmetricPrivateKey = veil::vtl1::crypto::bcrypt_import_private_key(loadedKeyBytes);
        SetAsymmetricPrivateKey(std::move(newAsymmetricPrivateKey));
        debug_print(L"Imported ECDSA private key from loaded user-bound key material");
    }
    else
    {
        debug_print(L"Asymmetric private key already loaded, using cached key");
    }

    return S_OK;
}

namespace RunTaskpoolExamples
{
    void Test_Dont_WaitForAllTasksToFinish(uint32_t threadCount)
    {
        using namespace veil::vtl1::vtl0_functions;

        debug_print(L"Creating taskpool with '%d' threads...", threadCount);

        auto tasks = std::vector<veil::vtl1::future<void>>();

        std::atomic<bool> ranLastTask = false;

        // taskpool
        {
            auto taskpool = veil::vtl1::taskpool(threadCount, false);

            // Use up all the threads
            for (uint32_t i = 0; i < threadCount; i++)
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

    void Test_Do_WaitForAllTasksToFinish(uint32_t threadCount)
    {
        using namespace veil::vtl1::vtl0_functions;

        debug_print(L"Creating taskpool with '%d' threads...", threadCount);

        auto tasks = std::vector<veil::vtl1::future<void>>();

        std::atomic<bool> ranLastTask = false;

        // taskpool
        {
            auto taskpool = veil::vtl1::taskpool(threadCount, true);

            // Use up all the threads
            for (uint32_t i = 0; i < threadCount; i++)
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

    void Test_Cancellation(uint32_t threadCount)
    {
        using namespace veil::vtl1::vtl0_functions;

        debug_print(L"Creating taskpool with '%d' threads...", threadCount);

        auto tasks = std::vector<veil::vtl1::future<void>>();

        std::atomic<bool> ranLastTask = false;

        // taskpool
        {
            auto taskpool = veil::vtl1::taskpool(threadCount, true);

            // Use up all the threads
            for (uint32_t i = 0; i < threadCount; i++)
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

    void UsageExample(uint32_t threadCount)
    {
        using namespace veil::vtl1::vtl0_functions;

        debug_print(L"Creating taskpool with '%d' threads...", threadCount);

        auto taskpool = veil::vtl1::taskpool(threadCount, true);

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

    void UsageExceptionExample(uint32_t threadCount)
    {
        using namespace veil::vtl1::vtl0_functions;

        debug_print(L"Creating taskpool with '%d' threads...", threadCount);

        auto taskpool = veil::vtl1::taskpool(threadCount, true);

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
HRESULT VbsEnclave::Trusted::Implementation::RunTaskpoolExample(_In_ const std::uint32_t threadCount)
{
    using namespace veil::vtl1::vtl0_functions;

    debug_print(L"TEST: Taskpool destruction, don't wait for all tasks to finish");
    RunTaskpoolExamples::Test_Dont_WaitForAllTasksToFinish(threadCount);
    debug_print(L"");

    debug_print(L"TEST: Taskpool destruction, wait for all tasks to finish");
    RunTaskpoolExamples::Test_Do_WaitForAllTasksToFinish(threadCount);
    debug_print(L"");

    debug_print(L"TEST: Taskpool cancellation");
    RunTaskpoolExamples::Test_Cancellation(threadCount);
    debug_print(L"");

    debug_print(L"USAGE");
    RunTaskpoolExamples::UsageExample(threadCount);
    debug_print(L"");

    debug_print(L"USAGE EXCEPTIONS");
    RunTaskpoolExamples::UsageExceptionExample(threadCount);
    debug_print(L"");

    return S_OK;
}

//
// User bound encryption key
//
HRESULT VbsEnclave::Trusted::Implementation::MyEnclaveCreateUserBoundKey(
    _In_ const std::wstring& helloKeyName,
    _In_ const std::wstring& pinMessage,
    _In_ const uintptr_t windowId,
    _In_ const uint32_t keyCredentialCacheOption,
    _Out_ std::vector<std::uint8_t>& securedEncryptionKeyBytes)
{
    using namespace veil::vtl1::vtl0_functions;

    try
    {
        debug_print(L"Start MyEnclaveCreateUserBoundKey");

        // VTL1 creates secure cache configuration - VTL0 input is ignored
        auto secureConfig = CreateSecureKeyCredentialCacheConfig();

        debug_print(L"Created secure cache configuration in VTL1");

        // Create a user-bound key with enclave sealing
        auto keyBytes = veil::vtl1::userboundkey::create_user_bound_key(
            helloKeyName,
            secureConfig,
            pinMessage,
            windowId,
            ENCLAVE_SEALING_IDENTITY_POLICY::ENCLAVE_IDENTITY_POLICY_SEAL_SAME_IMAGE,
            g_runtimePolicy,
            keyCredentialCacheOption);
        debug_print(L"create_user_bound_key returned");

        // Store the user-bound key bytes directly - do NOT try to create a symmetric key from them
        securedEncryptionKeyBytes.assign(keyBytes.begin(), keyBytes.end());
        
        // Do NOT try to create a symmetric key here - user-bound keys must be loaded properly
        // g_encryptionKey will be set in the load functions

        return S_OK;
    }
    CATCH_RETURN();
}

//
// Load user bound key and encrypt data
//
HRESULT VbsEnclave::Trusted::Implementation::MyEnclaveLoadUserBoundKeyAndEncryptData(
    _In_ const std::wstring& helloKeyName,
    _In_ const std::wstring& pinMessage,
    _In_ const uintptr_t windowId,
    _In_ const std::vector<std::uint8_t>& securedEncryptionKeyBytes,
    _In_ const std::wstring& inputData,
    _Out_ std::vector<std::uint8_t>& combinedOutputData,
    _Out_ bool& needsReseal,
    _Out_ std::vector<std::uint8_t>& resealedEncryptionKeyBytes)
{
    using namespace veil::vtl1::vtl0_functions;

    // Initialize output parameters
    needsReseal = false;
    resealedEncryptionKeyBytes.clear();

    try
    {
        debug_print(L"Start MyEnclaveLoadUserBoundKeyAndEncryptData");

        // Ensure the user-bound key is loaded (handles reseal if needed)
        RETURN_IF_FAILED(EnsureUserBoundKeyLoaded(
            helloKeyName,
            pinMessage,
            windowId,
            securedEncryptionKeyBytes,
            needsReseal,
            resealedEncryptionKeyBytes));

        // Use the global key for encryption
        debug_print(L"Encrypting input data");
        auto keyHandle = GetEncryptionKeyHandle();
        auto [encryptedText, encryptionTag] = veil::vtl1::crypto::encrypt(
            keyHandle, 
            veil::vtl1::as_data_span(inputData.c_str()), 
            veil::vtl1::crypto::zero_nonce);

        debug_print(L"Encryption completed, encrypted size: %d, tag size: %d", 
            encryptedText.size(), encryptionTag.size());

        // Combine tag and encrypted data into single output
        // Format: [tag_size (4 bytes)][tag_data][encrypted_data]
        uint32_t tagSize = static_cast<uint32_t>(encryptionTag.size());
        combinedOutputData.clear();
        combinedOutputData.reserve(sizeof(tagSize) + encryptionTag.size() + encryptedText.size());
  
        // Append tag size (4 bytes) at the beginning
        const uint8_t* tagSizeBytes = reinterpret_cast<const uint8_t*>(&tagSize);
        combinedOutputData.insert(combinedOutputData.end(), tagSizeBytes, tagSizeBytes + sizeof(tagSize));
  
        // Append tag data
        combinedOutputData.insert(combinedOutputData.end(), encryptionTag.begin(), encryptionTag.end());
 
        // Append encrypted data
        combinedOutputData.insert(combinedOutputData.end(), encryptedText.begin(), encryptedText.end());

        debug_print(L"Combined data created, total size: %u (tag_size: %u, tag: %u, encrypted: %u)", 
            static_cast<uint32_t>(combinedOutputData.size()), 
            static_cast<uint32_t>(sizeof(tagSize)),
            static_cast<uint32_t>(encryptionTag.size()), 
            static_cast<uint32_t>(encryptedText.size()));
    }
    CATCH_RETURN();

    return S_OK;
}

//
// Load user bound key and decrypt data
//
HRESULT VbsEnclave::Trusted::Implementation::MyEnclaveLoadUserBoundKeyAndDecryptData(
    _In_ const std::wstring& helloKeyName,
    _In_ const std::wstring& pinMessage,
    _In_ const uintptr_t windowId,
    _In_ const std::vector<std::uint8_t>& securedEncryptionKeyBytes,
    _In_ const std::vector<std::uint8_t>& combinedInputData,
    _Out_ std::wstring& decryptedData,
    _Out_ bool& needsReseal,
    _Out_ std::vector<std::uint8_t>& resealedEncryptionKeyBytes)
{
    using namespace veil::vtl1::vtl0_functions;

    // Initialize output parameters
    needsReseal = false;
    resealedEncryptionKeyBytes.clear();

    try
    {
        debug_print(L"Start MyEnclaveLoadUserBoundKeyAndDecryptData");

        // Extract tag from the combined input data
        // Format: [tag_size (4 bytes)][tag_data][encrypted_data]
        if (combinedInputData.size() < sizeof(uint32_t))
        {
            debug_print(L"ERROR: Combined input data too small, size: %u", static_cast<uint32_t>(combinedInputData.size()));
            return E_INVALIDARG;
        }

        // Read tag size from the first 4 bytes
        uint32_t tagSize;
        std::memcpy(&tagSize, combinedInputData.data(), sizeof(uint32_t));
 
        debug_print(L"Extracted tag size: %d", tagSize);

        // Validate tag size
        if (tagSize > combinedInputData.size() - sizeof(uint32_t) || tagSize == 0)
        {  
            debug_print(L"ERROR: Invalid tag size: %u, combined data size: %u", tagSize, static_cast<uint32_t>(combinedInputData.size()));
            return E_INVALIDARG;
        }

        auto it = combinedInputData.begin() + sizeof(uint32_t);

        // Extract tag data (after tag size)
        std::vector<uint8_t> tag(
            it,
            it + tagSize
        );
        it += tagSize;

        // Extract encrypted data (everything after tag size and tag data)
        std::vector<uint8_t> encryptedInputBytes(
            it,
            combinedInputData.end()
        );

        debug_print(L"Extracted tag size: %u, encrypted data size: %u", 
            static_cast<uint32_t>(tag.size()), 
            static_cast<uint32_t>(encryptedInputBytes.size()));

        // Ensure the user-bound key is loaded (handles reseal if needed)
        RETURN_IF_FAILED(EnsureUserBoundKeyLoaded(
            helloKeyName,
            pinMessage,
            windowId,
            securedEncryptionKeyBytes,
            needsReseal,
            resealedEncryptionKeyBytes));

        // Use the global key for decryption
        debug_print(L"Decrypting input data, encrypted size: %u, tag size: %u", 
            static_cast<uint32_t>(encryptedInputBytes.size()), 
            static_cast<uint32_t>(tag.size()));
  
        auto keyHandle = GetEncryptionKeyHandle();
        auto decryptedBytes = veil::vtl1::crypto::decrypt(
            keyHandle, 
            encryptedInputBytes, 
            veil::vtl1::crypto::zero_nonce, 
            tag);

        // Convert decrypted bytes to wstring
        decryptedData = veil::vtl1::to_wstring(decryptedBytes);
        
        debug_print(L"Decryption completed, decrypted string: %ws", decryptedData.c_str());
    }
    CATCH_RETURN();

    return S_OK;
}

//
// Secured encryption key
//
HRESULT VbsEnclave::Trusted::Implementation::RunEncryptionKeyExample_CreateEncryptionKey(_In_ const std::uint32_t activity_level, _In_ const std::wstring& logFilePath, _Out_  std::vector<std::uint8_t>& securedEncryptionKeyBytes)
{
    using namespace veil::vtl1::vtl0_functions;
    
    auto activityLevel = (veil::any::logger::eventLevel)activity_level;

    veil::vtl1::logger::add_log_from_enclave(
        L"[Enclave] In RunEncryptionKeyExample_CreateEncryptionKeyImpl", 
        veil::any::logger::eventLevel::EVENT_LEVEL_CRITICAL,
        activityLevel,
        logFilePath);

    debug_print("");
    debug_print(L"[Create flow]");
    debug_print("");
    veil::vtl1::logger::add_log_from_enclave(
        L"[Enclave] Create flow", 
        veil::any::logger::eventLevel::EVENT_LEVEL_VERBOSE,
        activityLevel,
        logFilePath);
    
    debug_print("");

    // Generate our encryption key
    debug_print(L"1. Generating our encryption key");
    veil::vtl1::logger::add_log_from_enclave(
        L"[Enclave] Generating our encryption key",
        veil::any::logger::eventLevel::EVENT_LEVEL_INFO,
        activityLevel,
        logFilePath);
    auto encryptionKeyBytes = veil::vtl1::crypto::generate_symmetric_key_bytes();
    debug_print(L" ...CHECKPOINT: encryption key byte count: %d", encryptionKeyBytes.size());
    std::wstring logSizeStr = std::to_wstring(encryptionKeyBytes.size());
    veil::vtl1::logger::add_log_from_enclave(
        L"[Enclave] Encryption key byte count: " + logSizeStr,
        veil::any::logger::eventLevel::EVENT_LEVEL_CRITICAL,
        activityLevel,
        logFilePath);
    debug_print("");
    
    // Seal the key using enclave sealing policy
    debug_print(L"4. Sealing the serialized key material for our enclave only");
    veil::vtl1::logger::add_log_from_enclave(
        L"[Enclave] Sealing the serialized key material for our enclave only",
        veil::any::logger::eventLevel::EVENT_LEVEL_INFO,
        activityLevel,
        logFilePath);

    // Seal the key using enclave sealing policy
    auto sealedKeyMaterial = veil::vtl1::crypto::seal_data(encryptionKeyBytes, ENCLAVE_IDENTITY_POLICY_SEAL_SAME_IMAGE, g_runtimePolicy);
    debug_print(L" ...CHECKPOINT: sealed key material byte count: %d", sealedKeyMaterial.size());
    logSizeStr = std::to_wstring(sealedKeyMaterial.size());
    veil::vtl1::logger::add_log_from_enclave(
        L"[Enclave] Sealed key material byte count: " + logSizeStr,
        veil::any::logger::eventLevel::EVENT_LEVEL_CRITICAL,
        activityLevel,
        logFilePath);
    debug_print("");

    // Erase our plain-text encryption key, (not necessary, but being explicit that we do not need this data anymore)
    encryptionKeyBytes.fill(0);

    // Return the secured encryption key to vtl0 host caller...
    securedEncryptionKeyBytes.assign(sealedKeyMaterial.begin(), sealedKeyMaterial.end());

    return S_OK;
}

HRESULT RunEncryptionKeyExample_LoadEncryptionKeyImpl(
    _In_ const std::vector<std::uint8_t>& securedEncryptionKeyBytes,
    _In_ const std::wstring& dataToEncrypt,
    _In_ const bool isToBeEncrypted,
    _In_ const std::uint32_t activity_level,
    _In_ const std::wstring& logFilePath,
    _Out_  std::vector<std::uint8_t>& resealedEncryptionKeyBytes,
    _Out_  std::vector<std::uint8_t>& encryptedInputBytes,
    _Out_  std::vector<std::uint8_t>& tag,
    _Out_  std::wstring& decryptedInputBytes,
    _In_ bool calledFromThreadpool = false,
    _In_ std::wstring logPrefix = L"",
    _Inout_opt_  std::vector<std::uint8_t>* threadpool_encryptedInputBytes = nullptr,
    _Inout_opt_  std::vector<std::uint8_t>* threadpool_encryptionTag = nullptr,
    _Inout_opt_  std::wstring* threadpool_decryptedInputBytes = nullptr)
{
    using namespace veil::vtl1::vtl0_functions;

    auto activityLevel = (veil::any::logger::eventLevel)activity_level;

    veil::vtl1::logger::add_log_from_enclave(
        L"[Enclave] In RunEncryptionKeyExample_LoadEncryptionKeyImpl",
        veil::any::logger::eventLevel::EVENT_LEVEL_CRITICAL,
        activityLevel,
        logFilePath);

    debug_print("%ws", logPrefix.c_str());
    debug_print("");
    debug_print(L"[Load flow]");
    debug_print("");

    debug_print("%ws", logPrefix.c_str());
    debug_print(L"1. Unsealing our encryption key (only our enclave can succeed this operation)");
    auto [unsealedBytes, unsealingFlags] = veil::vtl1::crypto::unseal_data(securedEncryptionKeyBytes);
    debug_print("%ws", logPrefix.c_str());
    debug_print(L" ...CHECKPOINT: unsealed byte count: = %d", unsealedBytes.size());
    debug_print("");

    // Create the symmetric key from unsealed bytes
    auto encryptionKey = veil::vtl1::crypto::create_symmetric_key(unsealedBytes);

   if (isToBeEncrypted)
   {
       // Encrypt the user input data
       auto const SOME_PLAIN_TEXT = dataToEncrypt.c_str();

       debug_print("%ws", logPrefix.c_str());
       debug_print(L"2. Encrypting input text.");
       auto [encryptedText, encryptionTag] = veil::vtl1::crypto::encrypt(encryptionKey.get(), veil::vtl1::as_data_span(SOME_PLAIN_TEXT), veil::vtl1::crypto::zero_nonce);
       debug_print("%ws", logPrefix.c_str());
       debug_print(L" ...CHECKPOINT: encrypted text's byte count: = %d", encryptedText.size());
       debug_print("");

       if (!calledFromThreadpool)
       {
           // Return the encrypted input to vtl0 host caller...
           encryptedInputBytes.assign(encryptedText.begin(), encryptedText.end());
           tag.assign(encryptionTag.begin(), encryptionTag.end());
       }
       else
       {
           // Return the encrypted input to vtl0 host caller...
           threadpool_encryptedInputBytes->assign(encryptedText.begin(), encryptedText.end());
           threadpool_encryptionTag->assign(encryptionTag.begin(), encryptionTag.end());
       }
   }
   else
   {
       // Decrypt the stored encrypted input
       debug_print("%ws", logPrefix.c_str());
       debug_print(L"3. Decrypting text...");
       auto decryptedText = veil::vtl1::crypto::decrypt(encryptionKey.get(), encryptedInputBytes, veil::vtl1::crypto::zero_nonce, tag);
       std::wstring decryptedString = veil::vtl1::to_wstring(decryptedText);
       debug_print("%ws", logPrefix.c_str());
       debug_print(L" ...CHECKPOINT: decrypted text: = %ws", decryptedString.c_str());
       debug_print("");

       if (!calledFromThreadpool)
       {
           // Return the decrypted input to vtl0 host caller...
           decryptedInputBytes = decryptedString;
       }
       else
       {
           // Return the decrypted input to vtl0 host caller...
           *threadpool_decryptedInputBytes = decryptedString;
       }
   }

   return true;
}

HRESULT VbsEnclave::Trusted::Implementation::RunEncryptionKeyExample_LoadEncryptionKey(_In_ const std::vector<std::uint8_t>& securedEncryptionKeyBytes,
    _In_ const std::wstring& dataToEncrypt,
    _In_ const bool isToBeEncrypted,
    _In_ const std::uint32_t activity_level,
    _In_ const std::wstring& logFilePath,
    _Out_  std::vector<std::uint8_t>& resealedEncryptionKeyBytes,
    _Out_  std::vector<std::uint8_t>& encryptedInputBytes,
    _Out_  std::vector<std::uint8_t>& tag,
    _Out_  std::wstring& decryptedInputBytes)
{
    RETURN_IF_FAILED(RunEncryptionKeyExample_LoadEncryptionKeyImpl(
        securedEncryptionKeyBytes,
        dataToEncrypt,
        isToBeEncrypted,
        activity_level,
        logFilePath,
        resealedEncryptionKeyBytes,
        encryptedInputBytes,
        tag,
        decryptedInputBytes
        ));
    return S_OK;
}

HRESULT VbsEnclave::Trusted::Implementation::RunEncryptionKeyExample_LoadEncryptionKeyThreadpool(_In_ const std::vector<std::uint8_t>& securedEncryptionKeyBytes, _In_ const std::wstring& dataToEncrypt1, _In_ const std::wstring& dataToEncrypt2, _In_ const bool isToBeEncrypted, _In_ const std::uint32_t activity_level, _In_ const std::wstring& logFilePath, _Out_  std::vector<std::uint8_t>& resealedEncryptionKeyBytes, _Inout_  std::vector<std::uint8_t>& encryptedInputBytes1, _Inout_  std::vector<std::uint8_t>& encryptedInputBytes2, _Inout_  std::vector<std::uint8_t>& tag1, _Inout_  std::vector<std::uint8_t>& tag2, _Out_  std::wstring& decryptedInputBytes1, _Out_  std::wstring& decryptedInputBytes2)
{
    using namespace veil::vtl1::vtl0_functions;
    auto threadCount = 2u;

    debug_print(L"Creating taskpool with '%d' threads...", threadCount);

    auto tasks = std::vector<veil::vtl1::future<void>>();

    std::atomic<bool> ranLastTask = false;

    // taskpool
    {
        auto taskpool = veil::vtl1::taskpool(threadCount, true);

        // Use up all the threads
        for (uint32_t i = 0; i < threadCount; i++)
        {
            auto task = taskpool.queue_task([&, i=i] ()
            {
                if (isToBeEncrypted)
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
                            isToBeEncrypted,
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
                }
                else
                {
                    debug_print(L"hello from decryption task: %d", i);

                    auto a = std::vector<uint8_t> {};
                    auto b = std::wstring {};
                    if (FAILED(RunEncryptionKeyExample_LoadEncryptionKeyImpl(
                        securedEncryptionKeyBytes,
                        {},
                        isToBeEncrypted,
                        activity_level,
                        logFilePath,
                        a,
                        (i == 0) ? encryptedInputBytes1 : encryptedInputBytes2,
                        (i == 0) ? tag1 : tag2,
                        b,
                        true /* called from threadPool */,
                        L"[THREAD " + std::to_wstring(i) + L"]",
                        nullptr,
                        nullptr,
                        (i == 0) ? &decryptedInputBytes1 : &decryptedInputBytes2)))
                    {
                    }
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

//
// Create asymmetric user-bound key pair (ECDSA)
//
HRESULT VbsEnclave::Trusted::Implementation::MyEnclaveCreateAsymmetricUserBoundKey(
    _In_ const std::wstring& helloKeyName,
    _In_ const std::wstring& pinMessage,
    _In_ const uintptr_t windowId,
    _In_ const uint32_t keyCredentialCreationOption,
    _Out_ std::vector<std::uint8_t>& securedPrivateKeyBytes,
    _Out_ std::vector<std::uint8_t>& publicKeyBytes)
{
    using namespace veil::vtl1::vtl0_functions;

    try
    {
        debug_print(L"Start MyEnclaveCreateAsymmetricUserBoundKey");

        // Generate ECDSA key pair
        auto keyPair = veil::vtl1::crypto::generate_ecdsa_key_pair();
        debug_print(L"Generated ECDSA key pair");

        // Export private key bytes
        auto privateKeyBytes = veil::vtl1::crypto::bcrypt_export_private_key(keyPair.get());
        debug_print((L"Exported private key, size: " + std::to_wstring(privateKeyBytes.size())).c_str());

        // Export public key bytes
        publicKeyBytes = veil::vtl1::crypto::bcrypt_export_public_key(keyPair.get());
        debug_print((L"Exported public key, size: " + std::to_wstring(publicKeyBytes.size())).c_str());

        // VTL1 creates secure cache configuration - VTL0 input is ignored
        auto secureConfig = CreateSecureKeyCredentialCacheConfig();
        debug_print(L"Created secure cache configuration in VTL1");

        // Create user-bound key using custom private key bytes
        auto sealedPrivateKeyBytes = veil::vtl1::userboundkey::create_user_bound_key(
            helloKeyName,
            secureConfig,
            pinMessage,
            windowId,
            ENCLAVE_SEALING_IDENTITY_POLICY::ENCLAVE_IDENTITY_POLICY_SEAL_SAME_IMAGE,
            g_runtimePolicy,
            keyCredentialCreationOption,
            privateKeyBytes);
        debug_print(L"create_user_bound_key with custom key bytes returned");

        // Store the secured private key bytes
        securedPrivateKeyBytes.assign(sealedPrivateKeyBytes.begin(), sealedPrivateKeyBytes.end());

        return S_OK;
    }
    CATCH_RETURN();
}

// Helper function to convert wstring to UTF-8 bytes for signing/verification
std::vector<uint8_t> wstring_to_utf8_bytes(const std::wstring& wstr)
{
    if (wstr.empty())
    {
        return {};
    }

    // Get the required buffer size
    int bytesNeeded = WideCharToMultiByte(
        CP_UTF8, 
        0, 
        wstr.c_str(), 
        static_cast<int>(wstr.length()),
        nullptr, 
        0, 
        nullptr, 
        nullptr);

    if (bytesNeeded <= 0)
    {
        THROW_HR(HRESULT_FROM_WIN32(GetLastError()));
    }

    // Convert to UTF-8
    std::vector<uint8_t> utf8Bytes(bytesNeeded);
    int result = WideCharToMultiByte(
        CP_UTF8,
        0,
        wstr.c_str(),
        static_cast<int>(wstr.length()),
        reinterpret_cast<char*>(utf8Bytes.data()),
        bytesNeeded,
        nullptr,
        nullptr);

    if (result != bytesNeeded)
    {
        THROW_HR(HRESULT_FROM_WIN32(GetLastError()));
    }

    return utf8Bytes;
}

//
// Sign data with user-bound private key
//
HRESULT VbsEnclave::Trusted::Implementation::MyEnclaveSignDataWithUserBoundKey(
    _In_ const std::wstring& helloKeyName,
    _In_ const std::wstring& pinMessage,
    _In_ const uintptr_t windowId,
    _In_ const std::vector<std::uint8_t>& securedPrivateKeyBytes,
    _In_ const std::wstring& dataToSign,
    _Out_ std::vector<std::uint8_t>& signature,
    _Out_ bool& needsReseal,
    _Out_ std::vector<std::uint8_t>& resealedPrivateKeyBytes)
{
    using namespace veil::vtl1::vtl0_functions;

    // Initialize output parameters
    needsReseal = false;
    resealedPrivateKeyBytes.clear();

    try
    {
        debug_print(L"Start MyEnclaveSignDataWithUserBoundKey");

        // Ensure the user-bound private key is loaded (handles reseal if needed)
        RETURN_IF_FAILED(EnsureAsymmetricUserBoundKeyLoaded(
            helloKeyName,
            pinMessage,
            windowId,
            securedPrivateKeyBytes,
            needsReseal,
            resealedPrivateKeyBytes));

        // Use the global cached private key for signing
        debug_print(L"Signing data with cached private key");
        auto privateKeyHandle = GetAsymmetricPrivateKeyHandle();

        // Convert wstring to UTF-8 bytes for signing
        auto utf8Data = wstring_to_utf8_bytes(dataToSign);
        debug_print((L"Converted data to UTF-8, size: " + std::to_wstring(utf8Data.size())).c_str());

        // Sign the data
        signature = veil::vtl1::crypto::ecdsa_sign(privateKeyHandle, utf8Data);
        debug_print((L"Signed data, signature size: " + std::to_wstring(signature.size())).c_str());

        return S_OK;
    }
    CATCH_RETURN();
}

//
// Verify signature with public key (no user interaction required)
//
HRESULT VbsEnclave::Trusted::Implementation::MyEnclaveVerifySignatureWithPublicKey(
    _In_ const std::vector<std::uint8_t>& publicKeyBytes,
    _In_ const std::wstring& dataToVerify,
    _In_ const std::vector<std::uint8_t>& signature,
    _Out_ bool& isValid)
{
    using namespace veil::vtl1::vtl0_functions;

    try
    {
        debug_print(L"Start MyEnclaveVerifySignatureWithPublicKey");

        // Import the public key
        auto publicKey = veil::vtl1::crypto::bcrypt_import_public_key_for_signature(publicKeyBytes);
        debug_print(L"Imported ECDSA public key");

        // Convert wstring to UTF-8 bytes for verification
        auto utf8Data = wstring_to_utf8_bytes(dataToVerify);
        debug_print((L"Converted data to UTF-8, size: " + std::to_wstring(utf8Data.size())).c_str());

        // Verify the signature
        isValid = veil::vtl1::crypto::ecdsa_verify(publicKey.get(), utf8Data, signature);
        debug_print((L"Signature verification result: " + std::wstring(isValid ? L"VALID" : L"INVALID")).c_str());

        return S_OK;
    }
    CATCH_RETURN();
}
