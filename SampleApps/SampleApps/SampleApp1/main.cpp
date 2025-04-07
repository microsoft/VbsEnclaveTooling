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

#include <sample_arguments.any.h>
#include "sample_utils.h"

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
    sample::args::RunHelloSecuredEncryptionKeyExample_CreateEncryptionKey data;
    data.helloKeyName = helloKeyName;
    data.activityLevel = veilLog.GetLogLevel();
    data.logFilePath = veilLog.GetLogFilePath();
    THROW_IF_FAILED(veil::vtl0::enclave::call_enclave(enclave, "RunHelloSecuredEncryptionKeyExample_CreateEncryptionKey", data));

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

    // Save securedEncryptionKeyBytes to disk
    SaveBinaryData(keyFilePath.string(), securedEncryptionKeyBytes);

    //
    // [Load flow]
    // 
    //  Pass the (encrypted) key bytes and the input into enclave to encrypt, store the encrypted bytes to disk
    //
    
    // Call into enclave
    sample::args::RunHelloSecuredEncryptionKeyExample_LoadEncryptionKey loadData;
    loadData.securedEncryptionKeyBytes.data = securedEncryptionKeyBytes.data();
    loadData.securedEncryptionKeyBytes.size = securedEncryptionKeyBytes.size();
    loadData.dataToEncrypt = input;
    loadData.isToBeEncrypted = true;
    loadData.activityLevel = veilLog.GetLogLevel();
    loadData.logFilePath = veilLog.GetLogFilePath();
    THROW_IF_FAILED(veil::vtl0::enclave::call_enclave(enclave, "RunHelloSecuredEncryptionKeyExample_LoadEncryptionKey", loadData));
    auto encryptedInputBytes = std::span<uint8_t>(reinterpret_cast<uint8_t*>(loadData.encryptedInputBytes.data), loadData.encryptedInputBytes.size);
    auto tag = std::span<uint8_t>(reinterpret_cast<uint8_t*>(loadData.tag.data), loadData.tag.size);

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
    sample::args::RunHelloSecuredEncryptionKeyExample_LoadEncryptionKey data;
    data.securedEncryptionKeyBytes.data = securedEncryptionKeyBytes.data();
    data.securedEncryptionKeyBytes.size = securedEncryptionKeyBytes.size();
    data.encryptedInputBytes.data = encryptedInputBytes.data();
    data.encryptedInputBytes.size = encryptedInputBytes.size();
    data.tag.data = tag.data();
    data.tag.size = tag.size();
    data.logFilePath = veilLog.GetLogFilePath();
    data.activityLevel = veilLog.GetLogLevel();
    THROW_IF_FAILED(veil::vtl0::enclave::call_enclave(enclave, "RunHelloSecuredEncryptionKeyExample_LoadEncryptionKey", data));

    auto decryptedInputBytes = std::span<uint8_t>(reinterpret_cast<uint8_t*>(data.decryptedInputBytes.data), data.decryptedInputBytes.size);

    std::wcout << L"Decryption completed in Enclave. Decrypted string: " << std::wstring(reinterpret_cast<const wchar_t*>(decryptedInputBytes.data()), decryptedInputBytes.size() / 2) << std::endl;
    veilLog.AddTimestampedLog(
        L"[Host] Decryption completed in Enclave. Decrypted string: " + std::wstring(reinterpret_cast<const wchar_t*>(decryptedInputBytes.data()), decryptedInputBytes.size() / 2), 
        veil::any::logger::eventLevel::EVENT_LEVEL_CRITICAL);

    return 0;
}

int EncryptFlowThreadpool(
    void* enclave,
    const std::wstring& input1,
    const std::wstring& input2,
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
    sample::args::RunHelloSecuredEncryptionKeyExample_CreateEncryptionKey data;
    data.helloKeyName = helloKeyName;
    data.activityLevel = veilLog.GetLogLevel();
    data.logFilePath = veilLog.GetLogFilePath();
    THROW_IF_FAILED(veil::vtl0::enclave::call_enclave(enclave, "RunHelloSecuredEncryptionKeyExample_CreateEncryptionKey", data));

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

    // Save securedEncryptionKeyBytes to disk
    SaveBinaryData(keyFilePath.string(), securedEncryptionKeyBytes);

    //
    // [Load flow]
    // 
    //  Pass the (encrypted) key bytes and the inputs into enclave to encrypt in threads, store the encrypted bytes to disk
    //

    // Call into enclave
    sample::args::RunHelloSecuredEncryptionKeyExample_LoadEncryptionKeyThreadpool loadData;
    loadData.securedEncryptionKeyBytes.data = securedEncryptionKeyBytes.data();
    loadData.securedEncryptionKeyBytes.size = securedEncryptionKeyBytes.size();
    loadData.dataToEncrypt1 = input1;
    loadData.dataToEncrypt2 = input2;
    loadData.isToBeEncrypted = true;
    loadData.activityLevel = veilLog.GetLogLevel();
    loadData.logFilePath = veilLog.GetLogFilePath();
    THROW_IF_FAILED(veil::vtl0::enclave::call_enclave(enclave, "RunHelloSecuredEncryptionKeyExample_LoadEncryptionKeyThreadpool", loadData));
    auto encryptedInputBytes1 = std::span<uint8_t>(reinterpret_cast<uint8_t*>(loadData.encryptedInputBytes1.data), loadData.encryptedInputBytes1.size);
    auto tag1 = std::span<uint8_t>(reinterpret_cast<uint8_t*>(loadData.tag1.data), loadData.tag1.size);
    auto encryptedInputBytes2 = std::span<uint8_t>(reinterpret_cast<uint8_t*>(loadData.encryptedInputBytes2.data), loadData.encryptedInputBytes2.size);
    auto tag2 = std::span<uint8_t>(reinterpret_cast<uint8_t*>(loadData.tag2.data), loadData.tag2.size);

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

    // Call into enclave
    sample::args::RunHelloSecuredEncryptionKeyExample_LoadEncryptionKeyThreadpool data;
    data.securedEncryptionKeyBytes.data = securedEncryptionKeyBytes.data();
    data.securedEncryptionKeyBytes.size = securedEncryptionKeyBytes.size();
    data.encryptedInputBytes1.data = encryptedInputBytes1.data();
    data.encryptedInputBytes1.size = encryptedInputBytes1.size();
    data.encryptedInputBytes2.data = encryptedInputBytes2.data();
    data.encryptedInputBytes2.size = encryptedInputBytes2.size();
    data.tag1.data = tag1.data();
    data.tag1.size = tag1.size();
    data.tag2.data = tag2.data();
    data.tag2.size = tag2.size();
    data.logFilePath = veilLog.GetLogFilePath();
    data.activityLevel = veilLog.GetLogLevel();
    THROW_IF_FAILED(veil::vtl0::enclave::call_enclave(enclave, "RunHelloSecuredEncryptionKeyExample_LoadEncryptionKeyThreadpool", data));

    auto decryptedInputBytes1 = std::span<uint8_t>(reinterpret_cast<uint8_t*>(data.decryptedInputBytes1.data), data.decryptedInputBytes1.size);
    auto decryptedInputBytes2 = std::span<uint8_t>(reinterpret_cast<uint8_t*>(data.decryptedInputBytes2.data), data.decryptedInputBytes2.size);

    std::wcout << L"Decryption completed in Enclave. Decrypted first string: " << std::wstring(reinterpret_cast<const wchar_t*>(decryptedInputBytes1.data()), decryptedInputBytes1.size() / 2) << std::endl;
    std::wcout << L"Decryption completed in Enclave. Decrypted second string: " << std::wstring(reinterpret_cast<const wchar_t*>(decryptedInputBytes2.data()), decryptedInputBytes2.size() / 2) << std::endl;
    veilLog.AddTimestampedLog(
        L"[Host] Decryption completed in Enclave. Decrypted first string: " + std::wstring(reinterpret_cast<const wchar_t*>(decryptedInputBytes1.data()), decryptedInputBytes1.size() / 2),
        veil::any::logger::eventLevel::EVENT_LEVEL_CRITICAL);
    veilLog.AddTimestampedLog(
        L"[Host] Decryption completed in Enclave. Decrypted second string: " + std::wstring(reinterpret_cast<const wchar_t*>(decryptedInputBytes2.data()), decryptedInputBytes2.size() / 2),
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
                std::wcout << L"Encryption in Enclave completed. Encrypted bytes are saved to disk in " << encryptedInputFilePath << std::endl;
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
    sample::args::RunTaskpoolExample data;
    data.threadCount = THREAD_COUNT - 1;
    THROW_IF_FAILED(veil::vtl0::enclave::call_enclave(enclave.get(), "RunTaskpoolExample", data));

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

    constexpr PCWSTR keyMoniker = L"MyHelloKey-001";

    // File with hello-secured encryption key bytes
    auto keyFilePath = std::filesystem::path(encrytedKeyDirPath) / keyMoniker;

    do
    {
        std::cout << "\n*** Multi-string Encryption and Decryption Menu ***\n";
        std::cout << "1. Encrypt strings\n";
        std::cout << "2. Decrypt strings\n";
        std::cout << "Enter your choice: ";
        std::cin >> choice;

        switch (choice)
        {
            case 1:
                std::cout << "Enter first string to encrypt: ";
                std::cin.ignore();
                std::getline(std::wcin, input1);
                std::cout << "Enter second string to encrypt: ";
                std::getline(std::wcin, input2);
                std::filesystem::create_directories(encryptedDataDirPath);
                std::filesystem::create_directories(encrytedKeyDirPath);
                EncryptFlowThreadpool(enclave.get(), input1, input2, keyMoniker, keyFilePath, encryptedInputFilePath, tagFilePath, veilLog);
                std::wcout << L"Encryption in Enclave threadpool completed. Encrypted bytes are saved to disk in " << encryptedInputFilePath << std::endl;;
                veilLog.AddTimestampedLog(
                    L"[Host] Encryption in Enclave threadpool completed. Encrypted bytes are saved to disk in " + encryptedInputFilePath,
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
