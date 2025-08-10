#include <iostream>
#include <fstream>
#include <string>
#include <conio.h> // For getch()
#include <filesystem> // For directory validation
#include <chrono>
#include <optional>

#include <windows.h>
#include <stdio.h>
#include <wil/resource.h>
#include <wil/result_macros.h>
#include <span>
#include <sddl.h>
#include <limits>
#include <ncrypt.h>  // Added for NCrypt functions

#include <winrt/base.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Security.Credentials.h>
#include <roapi.h>

#include <veil\host\enclave_api.vtl0.h>
#include <veil\host\logger.vtl0.h>

#include "sample_utils.h"

#include <VbsEnclave\HostApp\Trusted.h>

namespace fs = std::filesystem;

// Global variables (declared but not initialized, need to be encapsulated)
std::wstring g_helloKeyName;
std::wstring g_pinMessage;
std::optional<winrt::Windows::Security::Credentials::KeyCredentialCacheConfiguration> g_keyCredentialCacheConfig;
HWND g_hCurWnd;

// Initialize function to set up global variables
void Initialize()
{
    g_helloKeyName = L"MyEncryptionKey-001";
    g_pinMessage = L"Please enter your PIN to access the encryption key.";
    
    // Initialize COM for WinRT
    winrt::init_apartment();
    
    try 
    {
        // Use RoGetActivationFactory to get the factory for KeyCredentialCacheConfiguration
        winrt::com_ptr<winrt::Windows::Security::Credentials::IKeyCredentialCacheConfigurationFactory> factory;
        
        // Create HSTRING for the runtime class name
        winrt::hstring className = L"Windows.Security.Credentials.KeyCredentialCacheConfiguration";
        
        // Get the activation factory using RoGetActivationFactory
        HRESULT hr = RoGetActivationFactory(
            reinterpret_cast<HSTRING>(winrt::get_abi(className)),
            winrt::guid_of<winrt::Windows::Security::Credentials::IKeyCredentialCacheConfigurationFactory>(),
            factory.put_void()
        );
        
        if (SUCCEEDED(hr))
        {
            // Create the KeyCredentialCacheConfiguration instance using the factory
            /*
            auto cacheOption = winrt::Windows::Security::Credentials::KeyCredentialCacheOption::CacheWhenUnlocked;
            winrt::Windows::Foundation::TimeSpan timeout{std::chrono::seconds(300)}; // 5 minutes
            uint32_t usageCount = 5;
            */

            auto cacheOption = winrt::Windows::Security::Credentials::KeyCredentialCacheOption::NoCache;
            winrt::Windows::Foundation::TimeSpan timeout {std::chrono::seconds(0)}; // 5 minutes
            uint32_t usageCount = 0;
            
            // Use the factory ABI method with proper parameter types
            winrt::com_ptr<winrt::Windows::Security::Credentials::IKeyCredentialCacheConfiguration> instance;
            hr = factory->CreateInstance(
                static_cast<int32_t>(cacheOption),
                winrt::get_abi(timeout),
                usageCount,
                reinterpret_cast<void**>(instance.put())
            );
            
            if (SUCCEEDED(hr))
            {
                g_keyCredentialCacheConfig = winrt::Windows::Security::Credentials::KeyCredentialCacheConfiguration{ 
                    instance.detach(), winrt::take_ownership_from_abi 
                };
            }
            else
            {
                std::wcout << L"Warning: Failed to create KeyCredentialCacheConfiguration instance (HRESULT: 0x"
                           << std::hex << hr << L"). Using default cache configuration." << std::endl;
                g_keyCredentialCacheConfig = std::nullopt;
            }
        }
        else
        {
            std::wcout << L"Warning: Failed to get KeyCredentialCacheConfiguration factory (HRESULT: 0x"
                       << std::hex << hr << L"). Using default cache configuration." << std::endl;
            g_keyCredentialCacheConfig = std::nullopt;
        }
    }
    catch (winrt::hresult_error const& ex)
    {
        // If KeyCredentialCacheConfiguration is not available (e.g., older Windows versions),
        // leave g_keyCredentialCacheConfig as nullopt and handle gracefully
        std::wcout << L"Warning: KeyCredentialCacheConfiguration not available (HRESULT: 0x" 
                   << std::hex << ex.code() << L"). Using default cache configuration." << std::endl;
        g_keyCredentialCacheConfig = std::nullopt;
    }
    
    g_hCurWnd = GetForegroundWindow();
}

std::vector<uint8_t> OnFirstRun(void* enclave)
{
    Initialize();

    // Initialize enclave interface
    auto enclaveInterface = VbsEnclave::Trusted::Stubs::SampleEnclave(enclave);
    THROW_IF_FAILED(enclaveInterface.RegisterVtl0Callbacks());

    // Call into enclave
    auto securedEncryptionKeyBytes = std::vector<uint8_t> {};
    
    // Convert g_keyCredentialCacheConfig (WinRT type) to enclave keyCredentialCacheConfig (struct)
    VbsEnclave::DeveloperTypes::keyCredentialCacheConfig cacheConfig{};
    if (g_keyCredentialCacheConfig.has_value())
    {
        cacheConfig.cacheOption = static_cast<uint32_t>(g_keyCredentialCacheConfig->CacheOption());
        cacheConfig.cacheTimeoutInSeconds = static_cast<uint32_t>(g_keyCredentialCacheConfig->Timeout().count() / 10'000'000); // TimeSpan is in 100ns units
        cacheConfig.cacheUsageCount = static_cast<uint32_t>(g_keyCredentialCacheConfig->UsageCount());
    }
    else
    {
        // Use default values when KeyCredentialCacheConfiguration is not available
        cacheConfig.cacheOption = 1; // Default to CacheWhenUnlocked equivalent
        cacheConfig.cacheTimeoutInSeconds = 300; // 5 minutes
        cacheConfig.cacheUsageCount = 5;
    }

    THROW_IF_FAILED(enclaveInterface.MyEnclaveCreateUserBoundKey(
        g_helloKeyName,
        g_pinMessage,
        reinterpret_cast<uintptr_t>(g_hCurWnd), // <-- Fix: cast HWND to uintptr_t
        cacheConfig,
        securedEncryptionKeyBytes));

    return securedEncryptionKeyBytes;
    // *** securedEncryptionKeyBytes persisted to disk
}

int EncryptFlow(
    void* enclave, 
    const std::wstring& input, 
    const std::filesystem::path& keyFilePath,
    const std::filesystem::path& encryptedInputFilePath,
    const std::filesystem::path& tagFilePath,
    veil::vtl0::logger::logger& veilLog)
{
    //
    // [Create flow]
    // 
    //  Generate secured key in enclave, then pass the encrypted key bytes to vtl0
    //

    // Initialize enclave interface
    auto enclaveInterface = VbsEnclave::Trusted::Stubs::SampleEnclave(enclave);
    THROW_IF_FAILED(enclaveInterface.RegisterVtl0Callbacks());

    // Call into enclave
    auto securedEncryptionKeyBytes = std::vector<uint8_t> {};
    THROW_IF_FAILED(enclaveInterface.RunEncryptionKeyExample_CreateEncryptionKey(
        (const uint32_t)veilLog.GetLogLevel(),
        veilLog.GetLogFilePath(),
        securedEncryptionKeyBytes
    ));

    // We now have our encryption key's bytes, which are sealed!
    //
    //  Meaning of sealed:
    //
    //      1. Our encryption key is sealed by the enclave (i.e. can only be unsealed
    //          by the sealing-enclave or an enclave signed with compatible signature).

    // Save securedEncryptionKeyBytes to disk
    SaveBinaryData(keyFilePath.string(), securedEncryptionKeyBytes);

    //
    // [Load flow]
    // 
    //  Pass the (encrypted) key bytes and the input into enclave to encrypt, store the encrypted bytes to disk
    //

    // Call into enclave
    auto resealedEncryptionKeyBytes = std::vector<uint8_t> {};
    auto encryptedInputBytes = std::vector<uint8_t> {};
    auto tag = std::vector<uint8_t> {};
    auto decryptedData = std::wstring {};
    THROW_IF_FAILED(enclaveInterface.RunEncryptionKeyExample_LoadEncryptionKey(
        securedEncryptionKeyBytes,
        input,
        true,
        (const uint32_t)veilLog.GetLogLevel(),
        veilLog.GetLogFilePath(),
        // outs
        resealedEncryptionKeyBytes,
        // in/outs
        encryptedInputBytes,
        tag,
        // outs
        decryptedData
    ));

    // Save encryptedInputBytes to disk
    SaveBinaryData(encryptedInputFilePath.string(), encryptedInputBytes);
    SaveBinaryData(tagFilePath.string(), tag);

    return 0;
}

int DecryptFlow(
    void* enclave,
    const std::filesystem::path& keyFilePath,
    const std::filesystem::path& encryptedInputFilePath,
    const std::filesystem::path& tagFilePath,
    veil::vtl0::logger::logger& veilLog)
{
    //
    // [Load flow]
    // 
    //  Get (encrypted) key bytes from disk, then pass into enclave to decrypt the encrypted input
    //

    auto encryptedInputBytes = LoadBinaryData(encryptedInputFilePath.string());

    auto securedEncryptionKeyBytes = LoadBinaryData(keyFilePath.string());
    auto tag = LoadBinaryData(tagFilePath.string());

    // Initialize enclave interface
    auto enclaveInterface = VbsEnclave::Trusted::Stubs::SampleEnclave(enclave);
    THROW_IF_FAILED(enclaveInterface.RegisterVtl0Callbacks());

    // Call into enclave
    auto resealedEncryptionKeyBytes = std::vector<uint8_t> {};
    auto decryptedData = std::wstring {};
    THROW_IF_FAILED(enclaveInterface.RunEncryptionKeyExample_LoadEncryptionKey(
        securedEncryptionKeyBytes,
        {},
        false,
        (const uint32_t)veilLog.GetLogLevel(),
        veilLog.GetLogFilePath(),
        // outs
        resealedEncryptionKeyBytes,
        // in/outs
        encryptedInputBytes,
        tag,
        // outs
        decryptedData
    ));

    std::wcout << L"Decryption completed in Enclave. Decrypted string: " << decryptedData << std::endl;
    veilLog.AddTimestampedLog(
        L"[Host] Decryption completed in Enclave. Decrypted string: " + decryptedData,
        veil::any::logger::eventLevel::EVENT_LEVEL_CRITICAL);

    return 0;
}

int EncryptFlowThreadpool(
    void* enclave,
    const std::wstring& input1,
    const std::wstring& input2,
    const std::filesystem::path& keyFilePath,
    const std::filesystem::path& encryptedInputFilePath,
    const std::filesystem::path& tagFilePath,
    veil::vtl0::logger::logger& veilLog)
{
    //
    // [Create flow]
    // 
    //  Generate secured key in enclave, then pass the encrypted key bytes to vtl0
    //

    // Initialize enclave interface
    auto enclaveInterface = VbsEnclave::Trusted::Stubs::SampleEnclave(enclave);
    THROW_IF_FAILED(enclaveInterface.RegisterVtl0Callbacks());

    // Call into enclave
    auto securedEncryptionKeyBytes = std::vector<uint8_t> {};
    THROW_IF_FAILED(enclaveInterface.RunEncryptionKeyExample_CreateEncryptionKey(
        (const uint32_t)veilLog.GetLogLevel(),
        veilLog.GetLogFilePath(),
        securedEncryptionKeyBytes
    ));

    // We now have our encryption key's bytes, which are sealed!
    //
    //  Meaning of sealed:
    //
    //      1. Our encryption key is sealed by the enclave (i.e. can only be unsealed
    //          by the sealing-enclave or an enclave signed with compatible signature).

    // Save securedEncryptionKeyBytes to disk
    SaveBinaryData(keyFilePath.string(), securedEncryptionKeyBytes);

    //
    // [Load flow]
    // 
    //  Pass the (encrypted) key bytes and the inputs into enclave to encrypt in threads, store the encrypted bytes to disk
    //

    // Call into enclave
    auto resealedEncryptionKeyBytes = std::vector<uint8_t> {};
    auto encryptedInputBytes1 = std::vector<uint8_t> {};
    auto encryptedInputBytes2 = std::vector<uint8_t> {};
    auto tag1 = std::vector<uint8_t> {};
    auto tag2 = std::vector<uint8_t> {};
    auto decryptedInputBytes1 = std::wstring {};
    auto decryptedInputBytes2 = std::wstring {};
    THROW_IF_FAILED(enclaveInterface.RunEncryptionKeyExample_LoadEncryptionKeyThreadpool(
        securedEncryptionKeyBytes,
        input1,
        input2,
        true,
        (const uint32_t)veilLog.GetLogLevel(),
        veilLog.GetLogFilePath(),
        // outs
        resealedEncryptionKeyBytes,
        // in/outs
        encryptedInputBytes1,
        encryptedInputBytes2,
        tag1,
        tag2,
        // outs
        decryptedInputBytes1,
        decryptedInputBytes2
    ));

    // Save encryptedInputBytes to disk
    SaveBinaryData(encryptedInputFilePath.string().append("1"), encryptedInputBytes1);
    SaveBinaryData(tagFilePath.string().append("1"), tag1);
    SaveBinaryData(encryptedInputFilePath.string().append("2"), encryptedInputBytes2);
    SaveBinaryData(tagFilePath.string().append("2"), tag2);

    return 0;
}

int DecryptFlowThreadpool(
    void* enclave,
    const std::filesystem::path& keyFilePath,
    const std::filesystem::path& encryptedInputFilePath,
    const std::filesystem::path& tagFilePath,
    veil::vtl0::logger::logger& veilLog)
{
    //
    // [Load flow]
    // 
    //  Get (encrypted) key bytes from disk, then pass into enclave to decrypt the encrypted input
    //

    auto encryptedInputBytes1 = LoadBinaryData(encryptedInputFilePath.string().append("1"));
    auto encryptedInputBytes2 = LoadBinaryData(encryptedInputFilePath.string().append("2"));

    auto securedEncryptionKeyBytes = LoadBinaryData(keyFilePath.string());
    auto tag1 = LoadBinaryData(tagFilePath.string().append("1"));
    auto tag2 = LoadBinaryData(tagFilePath.string().append("2"));

    // Initialize enclave interface
    auto enclaveInterface = VbsEnclave::Trusted::Stubs::SampleEnclave(enclave);
    THROW_IF_FAILED(enclaveInterface.RegisterVtl0Callbacks());

    // Call into enclave
    auto resealedEncryptionKeyBytes = std::vector<uint8_t> {};
    auto decryptedInputBytes1 = std::wstring {};
    auto decryptedInputBytes2 = std::wstring {};
    THROW_IF_FAILED(enclaveInterface.RunEncryptionKeyExample_LoadEncryptionKeyThreadpool(
        securedEncryptionKeyBytes,
        {},
        {},
        false,
        (const uint32_t)veilLog.GetLogLevel(),
        veilLog.GetLogFilePath(),
        // outs
        resealedEncryptionKeyBytes,
        // in/outs
        encryptedInputBytes1,
        encryptedInputBytes2,
        tag1,
        tag2,
        // outs
        decryptedInputBytes1,
        decryptedInputBytes2
    ));

    std::wcout << L"Decryption completed in Enclave.\n Decrypted first string: " << decryptedInputBytes1 << std::endl;
    std::wcout << L"Decryption completed in Enclave.\n Decrypted second string: " << decryptedInputBytes2 << std::endl;
    veilLog.AddTimestampedLog(
        L"[Host] Decryption completed in Enclave. Decrypted first string: " + decryptedInputBytes1,
        veil::any::logger::eventLevel::EVENT_LEVEL_CRITICAL);
    veilLog.AddTimestampedLog(
        L"[Host] Decryption completed in Enclave. Decrypted second string: " + decryptedInputBytes2,
        veil::any::logger::eventLevel::EVENT_LEVEL_CRITICAL);
    return 0;
}

int mainEncryptDecrpyt(uint32_t activityLevel)
{
    int choice;
    std::wstring input;
    const std::wstring encryptedKeyDirPath = std::filesystem::current_path().wstring();
    const std::wstring encryptedDataDirPath = std::filesystem::current_path().wstring();
    std::wstring encryptedInputFilePath = encryptedDataDirPath + L"\\encrypted";
    std::wstring tagFilePath = encryptedKeyDirPath + L"\\tag";
    bool programExecuted = false;

    veil::vtl0::logger::logger veilLog(
        L"VeilSampleApp",
        L"70F7212C-1F84-4B86-B550-3D5AE82EC779" /*Generated GUID*/,
        static_cast<veil::any::logger::eventLevel>(activityLevel));

    veilLog.AddTimestampedLog(L"[Host] Starting from host", veil::any::logger::eventLevel::EVENT_LEVEL_CRITICAL);

    /******************************* Enclave setup *******************************/
    // Create app+user enclave identity - use the implemented owner_id function instead of NGC
    std::vector<uint8_t> ownerId;

    try 
    {
        wil::unique_ncrypt_prov ngcKsp;
        HRESULT hr = NCryptOpenStorageProvider(&ngcKsp, MS_NGC_KEY_STORAGE_PROVIDER, 0);
        if (SUCCEEDED(hr))
        {
            DWORD resultSize {};
            hr = NCryptGetProperty(
                ngcKsp.get(), L"NgcContainerSecureId", nullptr, 0, &resultSize, 0);
                
            if (SUCCEEDED(hr) && resultSize > 0)
            {
                std::vector<BYTE> ngcOwnerId(resultSize);
                hr = NCryptGetProperty(
                    ngcKsp.get(), L"NgcContainerSecureId", ngcOwnerId.data(), resultSize, &resultSize, 0);
                    
                if (SUCCEEDED(hr))
                {
                    ownerId = ngcOwnerId;
                }
            }
        }
    }
    catch (...)
    {
        // If NGC approach fails, continue with the default owner_id from the function
    }
        

    // Load enclave
    auto flags = ENCLAVE_VBS_FLAG_DEBUG;

    auto enclave = veil::vtl0::enclave::create(ENCLAVE_TYPE_VBS, ownerId, flags, veil::vtl0::enclave::megabytes(512));
    veil::vtl0::enclave::load_image(enclave.get(), L"sampleenclave.dll");
    veil::vtl0::enclave::initialize(enclave.get(), 2); // Note we need at 2 threads, otherwise we will have a reentrancy deadlock

    // Register framework callbacks
    veil::vtl0::enclave_api::register_callbacks(enclave.get());

    constexpr PCWSTR keyMoniker = L"MyEncryptionKey-001";

    // File with secured encryption key bytes
    auto keyFilePath = std::filesystem::path(encryptedKeyDirPath) / keyMoniker;

    do
    {
        std::cout << "\n*** String Encryption and Decryption Menu ***\n";
        std::cout << "1. Encrypt a string\n";
        std::cout << "2. Decrypt the string\n";
        std::cout << "Enter your choice: ";
        if (!(std::cin >> choice)) // Check if input is not an integer
        {
            std::cout << "Invalid input. Please enter a valid option (1 or 2).\n";
            std::cin.clear(); // Clear the error flag
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // Discard invalid input
            continue;
        }

        switch (choice)
        {
            case 1:
                std::cout << "Enter the string to encrypt: ";
                std::cin.ignore();
                std::getline(std::wcin, input);
                // EncryptFlow(enclave.get(), input, keyFilePath, encryptedInputFilePath, tagFilePath, veilLog);
                OnFirstRun(enclave.get()); // Ensure the key is created on first run
                std::wcout << L"Encryption in Enclave completed. \n Encrypted bytes are saved to disk in " << encryptedInputFilePath << std::endl;
                veilLog.AddTimestampedLog(
                    L"[Host] Encryption in Enclave completed. Encrypted bytes are saved to disk in " + encryptedInputFilePath,
                    veil::any::logger::eventLevel::EVENT_LEVEL_CRITICAL);
                programExecuted = true;
                break;

            case 2:
                DecryptFlow(enclave.get(), keyFilePath, encryptedInputFilePath, tagFilePath, veilLog);
                std::filesystem::remove(keyFilePath);
                std::filesystem::remove(encryptedInputFilePath);
                std::filesystem::remove(tagFilePath);
                programExecuted = true;
                break;

            default:
                std::cout << "Invalid choice. Please try again.\n";
        }
    }
    while (!programExecuted);

    // Wait for a key press before exiting
    std::cout << "\n\nPress any key to exit..." << std::endl;
    _getch();

    return 0;
}

int mainThreadPool(uint32_t /*activityLevel*/)
{
    std::wcout << L"Running sample: Taskpool..." << std::endl;

    // Create app+user enclave identity
    auto ownerId = veil::vtl0::appmodel::owner_id();

    // Load enclave
    auto flags = ENCLAVE_VBS_FLAG_DEBUG;

    // Let's arbitrarily choose to spawn 3 threads
    constexpr DWORD THREAD_COUNT = 3;

    auto enclave = veil::vtl0::enclave::create(ENCLAVE_TYPE_VBS, ownerId, flags, veil::vtl0::enclave::megabytes(512));
    veil::vtl0::enclave::load_image(enclave.get(), L"sampleenclave.dll");
    veil::vtl0::enclave::initialize(enclave.get(), THREAD_COUNT);

    // Register framework callbacks
    veil::vtl0::enclave_api::register_callbacks(enclave.get());

    // Initialize enclave interface
    auto enclaveInterface = VbsEnclave::Trusted::Stubs::SampleEnclave(enclave.get());
    THROW_IF_FAILED(enclaveInterface.RegisterVtl0Callbacks());

    // Call into enclave to 'RunTaskpoolExample' export
    THROW_IF_FAILED(enclaveInterface.RunTaskpoolExample(THREAD_COUNT - 1));

    std::wcout << L"Finished sample: Taskpool..." << std::endl;

    // Wait for a key press before exiting
    std::cout << "\n\nPress any key to exit..." << std::endl;
    _getch();

    return 0;
}

int mainEncryptDecrpytThreadpool(uint32_t activityLevel)
{
    std::wcout << L"Running sample: Encrypt decrypt in taskpool..." << std::endl;

    // Create app+user enclave identity
    auto ownerId = veil::vtl0::appmodel::owner_id();

    // Load enclave
    auto flags = ENCLAVE_VBS_FLAG_DEBUG;

    // Let's arbitrarily choose to spawn 2 threads
    constexpr DWORD THREAD_COUNT = 2;

    auto enclave = veil::vtl0::enclave::create(ENCLAVE_TYPE_VBS, ownerId, flags, veil::vtl0::enclave::megabytes(512));
    veil::vtl0::enclave::load_image(enclave.get(), L"sampleenclave.dll");
    veil::vtl0::enclave::initialize(enclave.get(), THREAD_COUNT);

    // Register framework callbacks
    veil::vtl0::enclave_api::register_callbacks(enclave.get());

    int choice;
    std::wstring input1, input2;
    const std::wstring encryptedKeyDirPath = std::filesystem::current_path().wstring();
    const std::wstring encryptedDataDirPath = std::filesystem::current_path().wstring();
    std::wstring encryptedInputFilePath = encryptedDataDirPath + L"\\encrypted";
    std::wstring tagFilePath = encryptedKeyDirPath + L"\\tag";
    bool programExecuted = false;

    veil::vtl0::logger::logger veilLog(
        L"VeilSampleApp",
        L"70F7212C-1F84-4B86-B550-3D5AE82EC779" /*Generated GUID*/,
        static_cast<veil::any::logger::eventLevel>(activityLevel));
    veilLog.AddTimestampedLog(L"[Host] Starting from host", veil::any::logger::eventLevel::EVENT_LEVEL_CRITICAL);

    constexpr PCWSTR keyMoniker = L"MyEncryptionKey-001";

    // File with secured encryption key bytes
    auto keyFilePath = std::filesystem::path(encryptedKeyDirPath) / keyMoniker;

    do
    {
        std::cout << "\n*** Multi-threaded encryption and decryption menu ***\n";
        std::cout << "1. Encrypt two strings\n";
        std::cout << "2. Decrypt the strings\n";
        std::cout << "Enter your choice: ";
        if (!(std::cin >> choice)) // Check if input is not an integer
        {
            std::cout << "Invalid input. Please enter a valid option (1 or 2).\n";
            std::cin.clear(); // Clear the error flag
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // Discard invalid input
            continue;
        }

        switch (choice)
        {
            case 1:
                std::cout << "Enter first string to encrypt: ";
                std::cin.ignore();
                std::getline(std::wcin, input1);
                std::cout << "Enter second string to encrypt: ";
                std::getline(std::wcin, input2);
                EncryptFlowThreadpool(enclave.get(), input1, input2, keyFilePath, encryptedInputFilePath, tagFilePath, veilLog);
                std::wcout << L"Encryption in Enclave threadpool completed. \n Encrypted bytes are saved to disk in " << encryptedDataDirPath << std::endl;;
                veilLog.AddTimestampedLog(
                    L"[Host] Encryption in Enclave threadpool completed. \n Encrypted bytes are saved to disk in " + encryptedDataDirPath,
                    veil::any::logger::eventLevel::EVENT_LEVEL_CRITICAL);
                programExecuted = true;
                break;

            case 2:
                DecryptFlowThreadpool(enclave.get(), keyFilePath, encryptedInputFilePath, tagFilePath, veilLog);
                std::filesystem::remove(keyFilePath);
                std::filesystem::remove(encryptedInputFilePath + L"1");
                std::filesystem::remove(encryptedInputFilePath + L"2");
                std::filesystem::remove(tagFilePath + L"1");
                std::filesystem::remove(tagFilePath + L"2");
                programExecuted = true;
                break;

            default:
                std::cout << "Invalid choice. Please try again.\n";
        }
    }
    while (!programExecuted);

    std::wcout << L"Finished sample: Encrypt Decrypt in taskpool..." << std::endl;

    // Wait for a key press before exiting
    std::cout << "\n\nPress any key to exit..." << std::endl;
    _getch();

    return 0;
}

int main(int argc, char* argv[])
{
    // Print diagnostic messages to the console for developer convenience
    wil::SetResultLoggingCallback([] (wil::FailureInfo const& failure) noexcept
    {
        wchar_t message[1024];
        wil::GetFailureLogString(message, ARRAYSIZE(message), failure);
        wprintf(L"Diagnostic message: %ls\n", message);
    });

    if (argc > 2)
    {
        std::cerr << "Usage: " << argv[0] << " <logging_level>" << std::endl;
        std::cerr << "Logging levels: 1 - Critical, 2 - Error, 3 - Warning, 4 - Info, 5 - Verbose" << std::endl;
        return 1;
    }

    uint32_t activityLevel = (argc == 2) ? std::atoi(argv[1]) : 4; //Info by default
    int choice;
    bool programExecuted = false;

    do
    {
        std::cout << "\n*** Sample App Menu ***\n";
        std::cout << "1. Encrypt, decrypt a string using enclave\n";
        std::cout << "2. Explore executing a threadpool in the enclave\n";
        std::cout << "3. Encrypt, decrypt multiple strings using threadpool and enclave\n";
        std::cout << "Enter your choice: ";
        if (!(std::cin >> choice)) // Check if input is not an integer
        {
            std::cout << "Invalid input. Please enter a valid option (1, 2 or 3).\n";
            std::cin.clear(); // Clear the error flag
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // Discard invalid input
            continue;
        }

        switch (choice)
        {
            case 1:
                mainEncryptDecrpyt(activityLevel);
                programExecuted = true;
                break;

            case 2:
                mainThreadPool(activityLevel);
                programExecuted = true;
                break;

            case 3:
                mainEncryptDecrpytThreadpool(activityLevel);
                programExecuted = true;
                break;

            default:
                std::cout << "Invalid choice. Please try again.\n";
        }
    }
    while (!programExecuted);

    return 0;
}
