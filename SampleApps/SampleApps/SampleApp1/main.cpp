#include <iostream>
#include <fstream>
#include <string>
#include <conio.h> // For getch()
#include <filesystem> // For directory validation

#include <windows.h>
#include <stdio.h>
#include <wil/resource.h>
#include <wil/result_macros.h>
#include <span>
#include <sddl.h>

#include <enclave_api.vtl0.h>
#include <logger.vtl0.h>

#include "sample_utils.h"

#include <VbsEnclave\HostApp\Stubs.h>

namespace fs = std::filesystem;

std::wstring FormatUserHelloKeyName(PCWSTR name)
{
    static constexpr wchar_t c_formatString[] = L"//{}//{}";
    wil::unique_hlocal_string userSidString;
    THROW_IF_WIN32_BOOL_FALSE(ConvertSidToStringSid(wil::get_token_information<TOKEN_USER>()->User.Sid, &userSidString));

    return std::format(c_formatString, userSidString.get(), name);
}

int EncryptFlow(
    void* enclave, 
    const std::wstring& input, 
    PCWSTR keyMoniker, 
    const std::filesystem::path& keyFilePath,
    const std::filesystem::path& encryptedInputFilePath,
    const std::filesystem::path& tagFilePath,
    veil::vtl0::logger::logger& veilLog)
{
    //
    // [Create flow]
    // 
    //  Generate hello-secured key in enclave, then pass the encrypted key bytes to vtl0
    //
    
    // Name of a hello key that will be the "root" of our encryption ancestry
    auto helloKeyName = FormatUserHelloKeyName(keyMoniker);

    // Call into enclave
    auto enclaveInterface = VbsEnclave::VTL0_Stubs::SampleEnclave(enclave);
    THROW_IF_FAILED(enclaveInterface.RegisterVtl0Callbacks());

    auto securedEncryptionKeyBytes = std::vector<uint8_t>{};
    THROW_IF_FAILED(enclaveInterface.RunHelloSecuredEncryptionKeyExample_CreateEncryptionKey(
        helloKeyName,
        (const uint32_t)veilLog.GetLogLevel(),
        veilLog.GetLogFilePath(),
        securedEncryptionKeyBytes
    ));

    // We now have our encryption key's bytes, which are "hello-secured" and sealed!
    //
    //  Meaning of "hello-secured" and sealed:
    //      1. Our encryption key is encrypted by a 'KEK' key (*not persisted anywhere*) that
    //          can only be re-materialized my NGC if user enters their Hello PIN or biometric auth
    //          ('proof of presence').
    //
    //      2. Our encryption key is sealed by the enclave (i.e. can only be unsealed
    //          by the sealing-enclave or an enclave signed with compatible signature).

    // Save securedEncryptionKeyBytes to disk
    SaveBinaryData(keyFilePath.string(), securedEncryptionKeyBytes);

    //
    // [Load flow]
    // 
    //  Pass the (encrypted) key bytes and the input into enclave to encrypt, store the encrypted bytes to disk
    //
    
    // Call into enclave
    auto resealedEncryptionKeyBytes = std::vector<uint8_t>{};
    auto encryptedInputBytes = std::vector<uint8_t>{};
    auto tag = std::vector<uint8_t>{};
    auto decryptedData = std::wstring{};
    THROW_IF_FAILED(enclaveInterface.RunHelloSecuredEncryptionKeyExample_LoadEncryptionKey(
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
    PCWSTR keyMoniker,
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

    // Call into enclave
    auto enclaveInterface = VbsEnclave::VTL0_Stubs::SampleEnclave(enclave);
    THROW_IF_FAILED(enclaveInterface.RegisterVtl0Callbacks());

    auto resealedEncryptionKeyBytes = std::vector<uint8_t>{};
    auto decryptedData = std::wstring{};
    THROW_IF_FAILED(enclaveInterface.RunHelloSecuredEncryptionKeyExample_LoadEncryptionKey(
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

    std::wcout << L"Decryption completed in Enclave. Decrypted string: " << decryptedData;
    veilLog.AddTimestampedLog(
        L"[Host] Decryption completed in Enclave. Decrypted string: " + decryptedData,
        veil::any::logger::eventLevel::EVENT_LEVEL_CRITICAL);

    return 0;
}

int mainEncryptDecrpyt(uint32_t activityLevel)
{
    int choice;
    std::wstring input;
    const std::wstring encrytedKeyDirPath = L"c:\\encrypted_key";
    const std::wstring encryptedDataDirPath = L"c:\\encrypted_data";
    std::wstring encryptedInputFilePath = encryptedDataDirPath + L"\\encrypted";
    std::wstring tagFilePath = encrytedKeyDirPath + L"\\tag";
    bool programExecuted = false;

    veil::vtl0::logger::logger veilLog(
        L"VeilSampleApp", 
        L"70F7212C-1F84-4B86-B550-3D5AE82EC779" /*Generated GUID*/,
        static_cast<veil::any::logger::eventLevel>(activityLevel));
    
    veilLog.AddTimestampedLog(L"[Host] Starting from host", veil::any::logger::eventLevel::EVENT_LEVEL_CRITICAL);

    /******************************* Enclave setup *******************************/
    // Create app+user enclave identity
    auto ownerId = veil::vtl0::appmodel::owner_id();

    // Load enclave
    auto flags = ENCLAVE_VBS_FLAG_DEBUG;

    auto enclave = veil::vtl0::enclave::create(ENCLAVE_TYPE_VBS, ownerId, flags, veil::vtl0::enclave::megabytes(512));
    veil::vtl0::enclave::load_image(enclave.get(), L"sampleenclave.dll");
    veil::vtl0::enclave::initialize(enclave.get(), 1);

    // Register framework callbacks
    veil::vtl0::enclave_api::register_callbacks(enclave.get());

    constexpr PCWSTR keyMoniker = L"MyHelloKey-001";

    // File with hello-secured encryption key bytes
    auto keyFilePath = std::filesystem::path(encrytedKeyDirPath) / keyMoniker;

    do
    {
        std::cout << "\n*** String Encryption and Decryption Menu ***\n";
        std::cout << "1. Encrypt a string\n";
        std::cout << "2. Decrypt the string\n";
        std::cout << "Enter your choice: ";
        std::cin >> choice;

        switch (choice)
        {
            case 1:
                std::cout << "Enter the string to encrypt: ";
                std::cin.ignore();
                std::getline(std::wcin, input);    
                std::filesystem::create_directories(encryptedDataDirPath);
                std::filesystem::create_directories(encrytedKeyDirPath);
                EncryptFlow(enclave.get(), input, keyMoniker, keyFilePath, encryptedInputFilePath, tagFilePath, veilLog);
                std::wcout << L"Encryption in Enclave completed. Encrypted bytes are saved to disk in " << encryptedInputFilePath;
                veilLog.AddTimestampedLog(
                    L"[Host] Encryption in Enclave completed. Encrypted bytes are saved to disk in " + encryptedInputFilePath,
                    veil::any::logger::eventLevel::EVENT_LEVEL_CRITICAL);
                programExecuted = true;
                break;

            case 2:
                DecryptFlow(enclave.get(), keyMoniker, keyFilePath, encryptedInputFilePath, tagFilePath, veilLog);
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

int mainThreadPool(uint32_t /*activityLevel*/ )
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

    // Call into enclave to 'RunTaskpoolExample' export
    auto enclaveInterface = VbsEnclave::VTL0_Stubs::SampleEnclave(enclave.get());
    THROW_IF_FAILED(enclaveInterface.RegisterVtl0Callbacks());
    THROW_IF_FAILED(enclaveInterface.RunTaskpoolExample(THREAD_COUNT - 1));

    std::wcout << L"Finished sample: Taskpool..." << std::endl;

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
        std::cout << "Enter your choice: ";
        std::cin >> choice;

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

            default:
                std::cout << "Invalid choice. Please try again.\n";
        }
    }
    while (!programExecuted);

    return 0;
}
