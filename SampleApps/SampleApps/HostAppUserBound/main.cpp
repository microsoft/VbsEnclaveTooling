#include <iostream>
#include <fstream>
#include <string>
#include <conio.h>
#include <filesystem>
#include <limits>

#include <windows.h>
#include <wil/resource.h>
#include <wil/result_macros.h>

#include <winrt/base.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Foundation.Metadata.h>
#include <winrt/Windows.Security.Credentials.h>
#include <winrt/Windows.Storage.Streams.h>
#include <roapi.h>

#include <veil\host\enclave_api.vtl0.h>
#include <veil\host\logger.vtl0.h>

#include "../Common/sample_utils.h"

#include <VbsEnclave\HostApp\Stubs\Trusted.h>

using namespace winrt::Windows::Security::Credentials;
using namespace winrt::Windows::Storage::Streams;

namespace fs = std::filesystem;

constexpr std::wstring_view KEY_NAME = L"MyEncryptionKey-001";

struct EncryptionConfig
{
    std::wstring helloKeyName;
    std::wstring pinMessage;
    HWND hCurWnd;
};

EncryptionConfig InitializeUserBindingConfig(bool& areUserBindingApisAvailable)
{
    EncryptionConfig config;
    config.helloKeyName = KEY_NAME;
    config.pinMessage = L"Please enter your PIN to access the encryption key.";
    
    winrt::init_apartment();
    
    try 
    {
        areUserBindingApisAvailable = 
            winrt::Windows::Foundation::Metadata::ApiInformation::IsTypePresent(L"Windows.Security.Credentials.KeyCredentialManager") &&
            winrt::Windows::Foundation::Metadata::ApiInformation::IsMethodPresent(L"Windows.Security.Credentials.KeyCredentialManager", L"GetSecureId");

        if (!areUserBindingApisAvailable)
        {
            std::wcout << L"Warning: User Binding APIs (KeyCredentialManager.GetSecureId) are not available on this system." << std::endl;
        }
    }
    catch (...)
    {
        std::wcout << L"Warning: Exception occurred while checking User Binding API availability." << std::endl;
        areUserBindingApisAvailable = false;
    }
    
    config.hCurWnd = GetForegroundWindow();
    return config;
}

EncryptionConfig CreateEncryptionKeyOnFirstRun(void* enclave, const fs::path& keyFilePath, const EncryptionConfig& config)
{
    auto enclaveInterface = VbsEnclave::Trusted::Stubs::SampleEnclave(enclave);
    THROW_IF_FAILED(enclaveInterface.RegisterVtl0Callbacks());

    auto securedEncryptionKeyBytes = std::vector<uint8_t> {};

    THROW_IF_FAILED(enclaveInterface.MyEnclaveCreateUserBoundKey(
        config.helloKeyName,
        config.pinMessage,
        reinterpret_cast<uintptr_t>(config.hCurWnd),
        static_cast<uint32_t>(KeyCredentialCreationOption::ReplaceExisting),
        securedEncryptionKeyBytes));

    SaveBinaryData(keyFilePath, securedEncryptionKeyBytes);
    
    return config;
}

void UserBoundEncryptFlow(
    void* enclave,
    const std::wstring& input,
    const fs::path& keyFilePath,
    const fs::path& encryptedOutputFilePath,
    const EncryptionConfig& config)
{
    auto enclaveInterface = VbsEnclave::Trusted::Stubs::SampleEnclave(enclave);
    THROW_IF_FAILED(enclaveInterface.RegisterVtl0Callbacks());

    auto securedEncryptionKeyBytes = LoadBinaryData(keyFilePath);

    auto combinedOutputData = std::vector<uint8_t> {};
    auto resealedEncryptionKeyBytes = std::vector<uint8_t> {};
    bool needsReseal = false;    

    THROW_IF_FAILED(enclaveInterface.MyEnclaveLoadUserBoundKeyAndEncryptData(
        config.helloKeyName,
        config.pinMessage,
        reinterpret_cast<uintptr_t>(config.hCurWnd),
        securedEncryptionKeyBytes,
        input,
        combinedOutputData,
        needsReseal,
        resealedEncryptionKeyBytes
    ));

    if (needsReseal && !resealedEncryptionKeyBytes.empty())
    {
        std::wcout << L"Key needs re-sealing, saving resealed key to disk..." << std::endl;
        std::wcout << L"Resealed key size: " << resealedEncryptionKeyBytes.size() << std::endl;
        SaveBinaryData(keyFilePath, resealedEncryptionKeyBytes);
    }
    SaveBinaryData(encryptedOutputFilePath, combinedOutputData);
}

void UserBoundDecryptFlow(
    void* enclave,
    const fs::path& keyFilePath,
    const fs::path& encryptedInputFilePath,
    const EncryptionConfig& config)
{
    auto enclaveInterface = VbsEnclave::Trusted::Stubs::SampleEnclave(enclave);
    THROW_IF_FAILED(enclaveInterface.RegisterVtl0Callbacks());

    auto securedEncryptionKeyBytes = LoadBinaryData(keyFilePath);
    auto combinedInputData = LoadBinaryData(encryptedInputFilePath);

    auto decryptedData = std::wstring {};
    auto resealedEncryptionKeyBytes = std::vector<uint8_t> {};
    bool needsReseal = false;

    THROW_IF_FAILED(enclaveInterface.MyEnclaveLoadUserBoundKeyAndDecryptData(
        config.helloKeyName,
        config.pinMessage,
        reinterpret_cast<uintptr_t>(config.hCurWnd),
        securedEncryptionKeyBytes,
        combinedInputData,
        decryptedData,
        needsReseal,
        resealedEncryptionKeyBytes
    ));

    if (needsReseal && !resealedEncryptionKeyBytes.empty())
    {
        std::wcout << L"Key needs re-sealing, saving resealed key to disk..." << std::endl;
        std::wcout << L"Resealed key size: " << resealedEncryptionKeyBytes.size() << std::endl;
        SaveBinaryData(keyFilePath, resealedEncryptionKeyBytes);
    }

    std::wcout << L"Decryption completed in Enclave. Decrypted string: " << decryptedData << std::endl;
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
    const fs::path encryptedOutputFilePath = encryptedDataDirPath / "encrypted_userbound";

    bool areUserBindingApisAvailable;
    auto config = InitializeUserBindingConfig(areUserBindingApisAvailable);

    if (!areUserBindingApisAvailable)
    {
        std::wcout << L"Error: User Binding APIs are not available on this system." << std::endl;
        std::wcout << L"This feature requires Windows Hello and appropriate hardware support." << std::endl;
        std::cout << "\nPress any key to exit..." << std::endl;
        _getch();
        return 1;
    }

    veil::vtl0::logger::logger veilLog(
        L"HostAppUserBound",
        L"C3D4E5F6-7890-1234-CDEF-345678901234",
        static_cast<veil::any::logger::eventLevel>(activityLevel));

    veilLog.AddTimestampedLog(L"[Host] Starting user-bound encryption from host", veil::any::logger::eventLevel::EVENT_LEVEL_CRITICAL);

    std::vector<uint8_t> ownerId;

    try
    {
        auto secureIdBuffer = KeyCredentialManager::GetSecureId();

        if (secureIdBuffer && secureIdBuffer.Length() > 0)
        {
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
        std::wcout << L"Error: Failed to get secure ID using GetSecureId API (HRESULT: 0x"
            << std::hex << ex.code() << L")." << std::endl;
        std::wcout << L"Cannot proceed without a valid secure ID for user-bound encryption." << std::endl;
        std::cout << "\nPress any key to exit..." << std::endl;
        _getch();
        return -1;
    }
    catch (...)
    {
        std::wcout << L"Error: Exception occurred while getting secure ID." << std::endl;
        std::wcout << L"Cannot proceed without a valid secure ID for user-bound encryption." << std::endl;
        std::cout << "\nPress any key to exit..." << std::endl;
        _getch();
        return -1;
    }

    auto flags = ENCLAVE_VBS_FLAG_DEBUG;

    auto enclave = veil::vtl0::enclave::create(ENCLAVE_TYPE_VBS, ownerId, flags, veil::vtl0::enclave::megabytes(512));
    veil::vtl0::enclave::load_image(enclave.get(), L"sampleenclave.dll");
    veil::vtl0::enclave::initialize(enclave.get(), 2);

    veil::vtl0::enclave_api::register_callbacks(enclave.get());

    constexpr PCWSTR keyMoniker = KEY_NAME.data();
    auto keyFilePath = encryptedKeyDirPath / keyMoniker;

    while (true)
    {
        std::cout << "\n*** User-Bound String Encryption and Decryption Menu ***\n";
        std::cout << "1. Encrypt a string (user-bound)\n";
        std::cout << "2. Decrypt the string (user-bound)\n";
        std::cout << "3. Exit\n";
        std::cout << "Enter your choice: ";
        
        if (!(std::cin >> choice))
        {
            std::cout << "Invalid input. Please enter a valid option (1, 2, or 3).\n";
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
                CreateEncryptionKeyOnFirstRun(enclave.get(), keyFilePath, config);
                UserBoundEncryptFlow(enclave.get(), input, keyFilePath, encryptedOutputFilePath, config);
                std::wcout << L"User-bound encryption in Enclave completed. \nEncrypted bytes are saved to disk in " << encryptedOutputFilePath << std::endl;
                veilLog.AddTimestampedLog(
                    L"[Host] User-bound encryption in Enclave completed. \nEncrypted bytes are saved to disk in " + encryptedOutputFilePath.wstring(),
                    veil::any::logger::eventLevel::EVENT_LEVEL_CRITICAL);
                break;

            case 2:
                UserBoundDecryptFlow(enclave.get(), keyFilePath, encryptedOutputFilePath, config);
                fs::remove(keyFilePath);
                fs::remove(encryptedOutputFilePath);
                break;

            case 3:
                std::cout << "Exiting program...\n";
                return 0;

            default:
                std::cout << "Invalid choice. Please try again.\n";
        }
    }
}
