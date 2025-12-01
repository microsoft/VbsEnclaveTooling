#include <iostream>
#include <fstream>
#include <string>
#include <conio.h>
#include <filesystem>
#include <limits>

#include <windows.h>
#include <wil/resource.h>
#include <wil/result_macros.h>

#include <veil\host\enclave_api.vtl0.h>
#include <veil\host\logger.vtl0.h>

#include "../Common/sample_utils.h"

#include <VbsEnclave\HostApp\Stubs\Trusted.h>

namespace fs = std::filesystem;

constexpr std::wstring_view KEY_NAME = L"MyEncryptionKey-001";

int EncryptFlowThreadpool(
    void* enclave,
    const std::wstring& input1,
    const std::wstring& input2,
    const fs::path& keyFilePath,
    const fs::path& encryptedInputFilePath,
    const fs::path& tagFilePath,
    veil::vtl0::logger::logger& veilLog)
{
    auto enclaveInterface = VbsEnclave::Trusted::Stubs::SampleEnclave(enclave);
    THROW_IF_FAILED(enclaveInterface.RegisterVtl0Callbacks());

    auto securedEncryptionKeyBytes = std::vector<uint8_t> {};
    THROW_IF_FAILED(enclaveInterface.RunEncryptionKeyExample_CreateEncryptionKey(
        (const uint32_t)veilLog.GetLogLevel(),
        veilLog.GetLogFilePath(),
        securedEncryptionKeyBytes
    ));

    SaveBinaryData(keyFilePath, securedEncryptionKeyBytes);

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
        resealedEncryptionKeyBytes,
        encryptedInputBytes1,
        encryptedInputBytes2,
        tag1,
        tag2,
        decryptedInputBytes1,
        decryptedInputBytes2
    ));

    SaveBinaryData(fs::path(encryptedInputFilePath.string() + "1"), encryptedInputBytes1);
    SaveBinaryData(fs::path(tagFilePath.string() + "1"), tag1);
    SaveBinaryData(fs::path(encryptedInputFilePath.string() + "2"), encryptedInputBytes2);
    SaveBinaryData(fs::path(tagFilePath.string() + "2"), tag2);

    return 0;
}

int DecryptFlowThreadpool(
    void* enclave,
    const fs::path& keyFilePath,
    const fs::path& encryptedInputFilePath,
    const fs::path& tagFilePath,
    veil::vtl0::logger::logger& veilLog)
{
    auto encryptedInputBytes1 = LoadBinaryData(fs::path(encryptedInputFilePath.string() + "1"));
    auto encryptedInputBytes2 = LoadBinaryData(fs::path(encryptedInputFilePath.string() + "2"));

    auto securedEncryptionKeyBytes = LoadBinaryData(keyFilePath);
    auto tag1 = LoadBinaryData(fs::path(tagFilePath.string() + "1"));
    auto tag2 = LoadBinaryData(fs::path(tagFilePath.string() + "2"));

    auto enclaveInterface = VbsEnclave::Trusted::Stubs::SampleEnclave(enclave);
    THROW_IF_FAILED(enclaveInterface.RegisterVtl0Callbacks());

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
        resealedEncryptionKeyBytes,
        encryptedInputBytes1,
        encryptedInputBytes2,
        tag1,
        tag2,
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

int main(int argc, char* argv[])
{
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

    uint32_t activityLevel = (argc == 2) ? std::atoi(argv[1]) : 4;

    std::wcout << L"Running sample: Encrypt decrypt in taskpool..." << std::endl;

    std::vector<uint8_t> ownerId = {};
    auto flags = ENCLAVE_VBS_FLAG_DEBUG;

    constexpr DWORD THREAD_COUNT = 2;

    auto enclave = veil::vtl0::enclave::create(ENCLAVE_TYPE_VBS, ownerId, flags, veil::vtl0::enclave::megabytes(512));
    veil::vtl0::enclave::load_image(enclave.get(), L"sampleenclave.dll");
    veil::vtl0::enclave::initialize(enclave.get(), THREAD_COUNT);

    veil::vtl0::enclave_api::register_callbacks(enclave.get());

    int choice;
    std::wstring input1, input2;
    const fs::path encryptedKeyDirPath = fs::current_path();
    const fs::path encryptedDataDirPath = fs::current_path();
    const fs::path encryptedInputFilePath = encryptedDataDirPath / "encrypted";
    const fs::path tagFilePath = encryptedKeyDirPath / "tag";
    bool programExecuted = false;

    veil::vtl0::logger::logger veilLog(
        L"HostAppEncryptDecryptThreadpool",
        L"B2C3D4E5-6F78-9012-BCDE-234567890123",
        static_cast<veil::any::logger::eventLevel>(activityLevel));
    veilLog.AddTimestampedLog(L"[Host] Starting from host", veil::any::logger::eventLevel::EVENT_LEVEL_CRITICAL);

    constexpr PCWSTR keyMoniker = KEY_NAME.data();
    auto keyFilePath = encryptedKeyDirPath / keyMoniker;

    do
    {
        std::cout << "\n*** Multi-threaded encryption and decryption menu ***\n";
        std::cout << "1. Encrypt two strings\n";
        std::cout << "2. Decrypt the strings\n";
        std::cout << "Enter your choice: ";
        if (!(std::cin >> choice))
        {
            std::cout << "Invalid input. Please enter a valid option (1 or 2).\n";
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
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
                std::wcout << L"Encryption in Enclave threadpool completed. \nEncrypted bytes are saved to disk in " << encryptedDataDirPath << std::endl;
                veilLog.AddTimestampedLog(
                    L"[Host] Encryption in Enclave threadpool completed. \nEncrypted bytes are saved to disk in " + encryptedDataDirPath.wstring(),
                    veil::any::logger::eventLevel::EVENT_LEVEL_CRITICAL);
                programExecuted = true;
                break;

            case 2:
                DecryptFlowThreadpool(enclave.get(), keyFilePath, encryptedInputFilePath, tagFilePath, veilLog);
                fs::remove(keyFilePath);
                fs::remove(fs::path(encryptedInputFilePath.string() + "1"));
                fs::remove(fs::path(encryptedInputFilePath.string() + "2"));
                fs::remove(fs::path(tagFilePath.string() + "1"));
                fs::remove(fs::path(tagFilePath.string() + "2"));
                programExecuted = true;
                break;

            default:
                std::cout << "Invalid choice. Please try again.\n";
        }
    }
    while (!programExecuted);

    std::wcout << L"Finished sample: Encrypt Decrypt in taskpool..." << std::endl;

    std::cout << "\n\nPress any key to exit..." << std::endl;
    _getch();

    return 0;
}
