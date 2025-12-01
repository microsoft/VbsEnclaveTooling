#include <iostream>
#include <fstream>
#include <string>
#include <conio.h> // For getch()
#include <filesystem> // For filesystem operations
#include <chrono>

#include <windows.h>
#include <stdio.h>
#include <wil/resource.h>
#include <wil/result_macros.h>
#include <span>
#include <sddl.h>
#include <limits>

#include <veil\host\enclave_api.vtl0.h>
#include <veil\host\logger.vtl0.h>

#include "../Common/sample_utils.h"

#include <VbsEnclave\HostApp\Stubs\Trusted.h>

namespace fs = std::filesystem;

constexpr std::wstring_view KEY_NAME = L"MyEncryptionKey-001";

int EncryptFlow(
    void* enclave, 
    const std::wstring& input, 
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
    auto encryptedInputBytes = std::vector<uint8_t> {};
    auto tag = std::vector<uint8_t> {};
    auto decryptedData = std::wstring {};
    THROW_IF_FAILED(enclaveInterface.RunEncryptionKeyExample_LoadEncryptionKey(
        securedEncryptionKeyBytes,
        input,
        true,
        (const uint32_t)veilLog.GetLogLevel(),
        veilLog.GetLogFilePath(),
        resealedEncryptionKeyBytes,
        encryptedInputBytes,
        tag,
        decryptedData
    ));

    SaveBinaryData(encryptedInputFilePath, encryptedInputBytes);
    SaveBinaryData(tagFilePath, tag);

    return 0;
}

int DecryptFlow(
    void* enclave,
    const fs::path& keyFilePath,
    const fs::path& encryptedInputFilePath,
    const fs::path& tagFilePath,
    veil::vtl0::logger::logger& veilLog)
{
    auto encryptedInputBytes = LoadBinaryData(encryptedInputFilePath);
    auto securedEncryptionKeyBytes = LoadBinaryData(keyFilePath);
    auto tag = LoadBinaryData(tagFilePath);

    auto enclaveInterface = VbsEnclave::Trusted::Stubs::SampleEnclave(enclave);
    THROW_IF_FAILED(enclaveInterface.RegisterVtl0Callbacks());

    auto resealedEncryptionKeyBytes = std::vector<uint8_t> {};
    auto decryptedData = std::wstring {};
    THROW_IF_FAILED(enclaveInterface.RunEncryptionKeyExample_LoadEncryptionKey(
        securedEncryptionKeyBytes,
        {},
        false,
        (const uint32_t)veilLog.GetLogLevel(),
        veilLog.GetLogFilePath(),
        resealedEncryptionKeyBytes,
        encryptedInputBytes,
        tag,
        decryptedData
    ));

    std::wcout << L"Decryption completed in Enclave. Decrypted string: " << decryptedData << std::endl;
    veilLog.AddTimestampedLog(
        L"[Host] Decryption completed in Enclave. Decrypted string: " + decryptedData,
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
    int choice;
    std::wstring input;
    const fs::path encryptedKeyDirPath = fs::current_path();
    const fs::path encryptedDataDirPath = fs::current_path();
    const fs::path encryptedOutputFilePath = encryptedDataDirPath / "encrypted";
    const fs::path tagFilePath = encryptedKeyDirPath / "tag";
    bool programExecuted = false;

    veil::vtl0::logger::logger veilLog(
        L"HostApp",
        L"A1B2C3D4-5E6F-7890-ABCD-123456789012",
        static_cast<veil::any::logger::eventLevel>(activityLevel));

    veilLog.AddTimestampedLog(L"[Host] Starting from host", veil::any::logger::eventLevel::EVENT_LEVEL_CRITICAL);

    std::vector<uint8_t> ownerId = {};
    auto flags = ENCLAVE_VBS_FLAG_DEBUG;

    auto enclave = veil::vtl0::enclave::create(ENCLAVE_TYPE_VBS, ownerId, flags, veil::vtl0::enclave::megabytes(512));
    veil::vtl0::enclave::load_image(enclave.get(), L"sampleenclave.dll");
    veil::vtl0::enclave::initialize(enclave.get(), 2);

    veil::vtl0::enclave_api::register_callbacks(enclave.get());

    constexpr PCWSTR keyMoniker = KEY_NAME.data();
    auto keyFilePath = encryptedKeyDirPath / keyMoniker;

    do
    {
        std::cout << "\n*** String Encryption and Decryption Menu ***\n";
        std::cout << "1. Encrypt a string\n";
        std::cout << "2. Decrypt the string\n";
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
                std::cout << "Enter the string to encrypt: ";
                std::cin.ignore();
                std::getline(std::wcin, input);
                EncryptFlow(enclave.get(), input, keyFilePath, encryptedOutputFilePath, tagFilePath, veilLog);
                std::wcout << L"Encryption in Enclave completed. \nEncrypted bytes are saved to disk in " << encryptedOutputFilePath << std::endl;
                veilLog.AddTimestampedLog(
                    L"[Host] Encryption in Enclave completed. Encrypted bytes are saved to disk in " + encryptedOutputFilePath.wstring(),
                    veil::any::logger::eventLevel::EVENT_LEVEL_CRITICAL);
                programExecuted = true;
                break;

            case 2:
                DecryptFlow(enclave.get(), keyFilePath, encryptedOutputFilePath, tagFilePath, veilLog);
                fs::remove(keyFilePath);
                fs::remove(encryptedOutputFilePath);
                fs::remove(tagFilePath);
                programExecuted = true;
                break;

            default:
                std::cout << "Invalid choice. Please try again.\n";
        }
    }
    while (!programExecuted);

    std::cout << "\n\nPress any key to exit..." << std::endl;
    _getch();

    return 0;
}
