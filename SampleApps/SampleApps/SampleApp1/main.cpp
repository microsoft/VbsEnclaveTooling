#include <iostream>
#include <fstream>
#include <string>
#include <conio.h> // For getch()
#include <filesystem> // For directory validation
#include <chrono>

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
#include <winrt/Windows.Storage.Streams.h>
#include <roapi.h>

#include <veil\host\enclave_api.vtl0.h>
#include <veil\host\logger.vtl0.h>

#include "sample_utils.h"

#include <VbsEnclave\HostApp\Stubs\Trusted.h>

using namespace winrt::Windows::Security::Credentials;

namespace fs = std::filesystem;

// Configuration structure
struct EncryptionConfig
{
    std::wstring helloKeyName;
    std::wstring pinMessage;
    HWND hCurWnd;
};

// Initialize function to set up configuration and determine API availability
EncryptionConfig InitializeUserBindingConfig(bool& areUserBindingApisAvailable)
{
    areUserBindingApisAvailable = true;
    EncryptionConfig config;
    config.helloKeyName = L"MyEncryptionKey-001";
    config.pinMessage = L"Please enter your PIN to access the encryption key.";
    
    // Initialize COM for WinRT
    winrt::init_apartment();
    
    // Check if User Binding APIs are available by attempting to create KeyCredentialCacheConfiguration
    try 
    {
        // Use RoGetActivationFactory to test if KeyCredentialCacheConfiguration is available
        winrt::com_ptr<winrt::Windows::Security::Credentials::IKeyCredentialCacheConfigurationFactory> factory;
        
        // Create HSTRING for the runtime class name
        winrt::hstring className = L"Windows.Security.Credentials.KeyCredentialCacheConfiguration";
        
        // Get the activation factory using RoGetActivationFactory
        THROW_IF_FAILED(RoGetActivationFactory(
            reinterpret_cast<HSTRING>(winrt::get_abi(className)),
            winrt::guid_of<winrt::Windows::Security::Credentials::IKeyCredentialCacheConfigurationFactory>(),
            factory.put_void()
        ));
    }
    catch (...)
    {
        // Any other exception means APIs are not available
        std::wcout << L"Warning: Exception occurred while checking User Binding API availability." << std::endl;
        areUserBindingApisAvailable = false;
    }
    
    config.hCurWnd = GetForegroundWindow();
    return config;
}

EncryptionConfig CreateEncryptionKeyOnFirstRun(void* enclave, const std::filesystem::path& keyFilePath, const EncryptionConfig& config)
{
    // Initialize enclave interface
    auto enclaveInterface = VbsEnclave::Trusted::Stubs::SampleEnclave(enclave);
    THROW_IF_FAILED(enclaveInterface.RegisterVtl0Callbacks());

    // Call into enclave
    auto securedEncryptionKeyBytes = std::vector<uint8_t> {};

    THROW_IF_FAILED(enclaveInterface.MyEnclaveCreateUserBoundKey(
        config.helloKeyName,
        config.pinMessage,
        reinterpret_cast<uintptr_t>(config.hCurWnd),
        static_cast<uint32_t>(KeyCredentialCreationOption::ReplaceExisting),
        securedEncryptionKeyBytes));

    // *** securedEncryptionKeyBytes persisted to disk
    SaveBinaryData(keyFilePath.string(), securedEncryptionKeyBytes);
    
    // Return the config so it can be used by subsequent functions
    return config;
}

void UserBoundEncryptFlow(
    void* enclave,
    const std::wstring& input,
    const std::filesystem::path& keyFilePath,
    const std::filesystem::path& encryptedOutputFilePath,
    const EncryptionConfig& config)
{
    // Initialize enclave interface
    auto enclaveInterface = VbsEnclave::Trusted::Stubs::SampleEnclave(enclave);
    THROW_IF_FAILED(enclaveInterface.RegisterVtl0Callbacks());

    //
    // [Load flow]
    // 
    //  Pass the (encrypted) key bytes and the input into enclave to encrypt, store the encrypted bytes to disk
    //

    // Load secured encryption key bytes from disk
    auto securedEncryptionKeyBytes = LoadBinaryData(keyFilePath.string());

    // Call into enclave - the enclave will return combined data (encrypted + tag + tag_size)
    auto combinedOutputData = std::vector<uint8_t> {};

    THROW_IF_FAILED(enclaveInterface.MyEnclaveLoadUserBoundKeyAndEncryptData(
        config.helloKeyName,
        config.pinMessage,
        reinterpret_cast<uintptr_t>(config.hCurWnd),
        securedEncryptionKeyBytes,
        input,
        combinedOutputData
    ));

    // Save combined data directly to disk (enclave handles the tag appending)
    SaveBinaryData(encryptedOutputFilePath.string(), combinedOutputData);
}

void UserBoundDecryptFlow(
    void* enclave,
    const std::filesystem::path& keyFilePath,
    const std::filesystem::path& encryptedInputFilePath,
    const EncryptionConfig& config)
{
    // Initialize enclave interface
    auto enclaveInterface = VbsEnclave::Trusted::Stubs::SampleEnclave(enclave);
    THROW_IF_FAILED(enclaveInterface.RegisterVtl0Callbacks());

    //
    // [Load flow]
    // 
    //  Load the (encrypted) key bytes and combined data from disk, then pass into enclave to decrypt
    //

    // Load data from disk
    auto securedEncryptionKeyBytes = LoadBinaryData(keyFilePath.string());
    auto combinedInputData = LoadBinaryData(encryptedInputFilePath.string());

    // Call into enclave for decryption - pass combined data, enclave will extract tag internally
    auto decryptedData = std::wstring {};

    THROW_IF_FAILED(enclaveInterface.MyEnclaveLoadUserBoundKeyAndDecryptData(
        config.helloKeyName,
        config.pinMessage,
        reinterpret_cast<uintptr_t>(config.hCurWnd),
        securedEncryptionKeyBytes,
        combinedInputData,
        decryptedData
    ));

    // Display the decrypted result
    std::wcout << L"Decryption completed in Enclave. Decrypted string: " << decryptedData << std::endl;
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

int mainEncryptDecrypt(uint32_t activityLevel)
{
    int choice;
    std::wstring input;
    const std::wstring encryptedKeyDirPath = std::filesystem::current_path().wstring();
    const std::wstring encryptedDataDirPath = std::filesystem::current_path().wstring();
    std::wstring encryptedOutputFilePath = encryptedDataDirPath + L"\\encrypted";
    std::wstring tagFilePath = encryptedKeyDirPath + L"\\tag";
    bool programExecuted = false;

    veil::vtl0::logger::logger veilLog(
        L"VeilSampleApp",
        L"70F7212C-1F84-4B86-B550-3D5AE82EC779" /*Generated GUID*/,
    static_cast<veil::any::logger::eventLevel>(activityLevel));

    veilLog.AddTimestampedLog(L"[Host] Starting from host", veil::any::logger::eventLevel::EVENT_LEVEL_CRITICAL);

    // Create app+user enclave identity
    std::vector<uint8_t> ownerId = {};

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
                EncryptFlow(enclave.get(), input, keyFilePath, encryptedOutputFilePath, tagFilePath, veilLog);
                std::wcout << L"Encryption in Enclave completed. \n Encrypted bytes are saved to disk in " << encryptedOutputFilePath << std::endl;
                veilLog.AddTimestampedLog(
                    L"[Host] Encryption in Enclave completed. Encrypted bytes are saved to disk in " + encryptedOutputFilePath,
                        veil::any::logger::eventLevel::EVENT_LEVEL_CRITICAL);
                programExecuted = true;
                break;

            case 2:
                DecryptFlow(enclave.get(), keyFilePath, encryptedOutputFilePath, tagFilePath, veilLog);
                std::filesystem::remove(keyFilePath);
                std::filesystem::remove(encryptedOutputFilePath);
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

int mainEncryptDecryptUserBound(uint32_t activityLevel)
{
    int choice;
    std::wstring input;
    const std::wstring encryptedKeyDirPath = std::filesystem::current_path().wstring();
    const std::wstring encryptedDataDirPath = std::filesystem::current_path().wstring();
    std::wstring encryptedOutputFilePath = encryptedDataDirPath + L"\\encrypted_userbound";
    bool programExecuted = false;

    // Initialize configuration for user-bound keys
    bool areUserBindingApisAvailable;
    auto config = InitializeUserBindingConfig(areUserBindingApisAvailable);

    if (!areUserBindingApisAvailable)
    {
        std::wcout << L"Error: User Binding APIs are not available on this system." << std::endl;
        std::wcout << L"This feature requires Windows Hello and appropriate hardware support." << std::endl;
        std::cout << "\nPress any key to return to main menu..." << std::endl;
        _getch();
        return 1;
    }

    veil::vtl0::logger::logger veilLog(
        L"VeilSampleApp",
        L"70F7212C-1F84-4B86-B550-3D5AE82EC779" /*Generated GUID*/,
    static_cast<veil::any::logger::eventLevel>(activityLevel));

    veilLog.AddTimestampedLog(L"[Host] Starting user-bound encryption from host", veil::any::logger::eventLevel::EVENT_LEVEL_CRITICAL);

    /******************************* Enclave setup *******************************/
    // Create app+user enclave identity - use the new GetSecureId API from IKeyCredentialManagerStatics2
    std::vector<uint8_t> ownerId;

    try
    {
        // Call the GetSecureId API directly on the static class
        auto secureIdBuffer = KeyCredentialManager::GetSecureId();

        if (secureIdBuffer && secureIdBuffer.Length() > 0)
        {
            // Convert IBuffer to std::vector<uint8_t>
            auto reader = winrt::Windows::Storage::Streams::DataReader::FromBuffer(secureIdBuffer);
            ownerId.resize(secureIdBuffer.Length());
            reader.ReadBytes(ownerId);
        }
        else
        {
            std::wcout << L"Warning: GetSecureId returned empty buffer." << std::endl;
            THROW_HR(E_UNEXPECTED);
        }
    }
    catch (winrt::hresult_error const& ex)
    {
        // If the new API is not available or fails, log the error and continue with default
        std::wcout << L"Warning: Failed to get secure ID using GetSecureId API (HRESULT: 0x"
            << std::hex << ex.code() << L"). Using default owner_id." << std::endl;
    }
    catch (...)
    {
        // If any other exception occurs, continue with default
        std::wcout << L"Warning: Exception occurred while getting secure ID. Using default owner_id." << std::endl;
    }

    // Fallback to the default owner_id if the new API failed or returned empty result
    if (ownerId.empty())
    {
        ownerId = {};
    }

    // Load enclave
    auto flags = ENCLAVE_VBS_FLAG_DEBUG;

    auto enclave = veil::vtl0::enclave::create(ENCLAVE_TYPE_VBS, ownerId, flags, veil::vtl0::enclave::megabytes(512));
    veil::vtl0::enclave::load_image(enclave.get(), L"sampleenclave.dll");
    veil::vtl0::enclave::initialize(enclave.get(), 2); // Note we need at 2 threads, otherwise we will have a reentrancy deadlock

    // Register framework callbacks
    veil::vtl0::enclave_api::register_callbacks(enclave.get());

    constexpr PCWSTR keyMoniker = L"MyEncryptionKey-UserBound-001";

    // File with secured encryption key bytes
    auto keyFilePath = std::filesystem::path(encryptedKeyDirPath) / keyMoniker;

    do
    {
        std::cout << "\n*** User-Bound String Encryption and Decryption Menu ***\n";
        std::cout << "1. Encrypt a string (user-bound)\n";
        std::cout << "2. Decrypt the string (user-bound)\n";
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
                CreateEncryptionKeyOnFirstRun(enclave.get(), keyFilePath, config);
                UserBoundEncryptFlow(enclave.get(), input, keyFilePath, encryptedOutputFilePath, config);
                std::wcout << L"User-bound encryption in Enclave completed. \n Encrypted bytes are saved to disk in " << encryptedOutputFilePath << std::endl;
                veilLog.AddTimestampedLog(
                    L"[Host] User-bound encryption in Enclave completed. Encrypted bytes are saved to disk in " + encryptedOutputFilePath,
                    veil::any::logger::eventLevel::EVENT_LEVEL_CRITICAL);
                programExecuted = true;
                break;

            case 2:
                UserBoundDecryptFlow(enclave.get(), keyFilePath, encryptedOutputFilePath, config);
                std::filesystem::remove(keyFilePath);
                std::filesystem::remove(encryptedOutputFilePath);
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
    std::vector<uint8_t> ownerId = {};

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

int mainEncryptDecryptThreadpool(uint32_t activityLevel)
{
    std::wcout << L"Running sample: Encrypt decrypt in taskpool..." << std::endl;

    // Create app+user enclave identity
    std::vector<uint8_t> ownerId = {};

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
                std::wcout << L"Encryption in Enclave threadpool completed. \n Encrypted bytes are saved to disk in " << encryptedDataDirPath << std::endl;
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
        std::cout << "4. Encrypt, decrypt a string using user-bound keys (Windows Hello)\n";
        std::cout << "Enter your choice: ";
        if (!(std::cin >> choice)) // Check if input is not an integer
        {
            std::cout << "Invalid input. Please enter a valid option (1, 2, 3 or 4).\n";
            std::cin.clear(); // Clear the error flag
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); // Discard invalid input
            continue;
        }

        switch (choice)
        {
            case 1:
                mainEncryptDecrypt(activityLevel);
                programExecuted = true;
                break;

            case 2:
                mainThreadPool(activityLevel);
                programExecuted = true;
                break;

            case 3:
                mainEncryptDecryptThreadpool(activityLevel);
                programExecuted = true;
                break;

            case 4:
                mainEncryptDecryptUserBound(activityLevel);
                programExecuted = true;
                break;

            default:
                std::cout << "Invalid choice. Please try again.\n";
        }
    }
    while (!programExecuted);

    return 0;
}
