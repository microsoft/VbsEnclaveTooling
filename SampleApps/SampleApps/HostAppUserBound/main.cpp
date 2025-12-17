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

template <typename T>
concept CanGetSecureId =
    requires { { T::GetSecureId() }; };

// Key management helper functions
void CreateUBKey(void* enclave, const fs::path& keyFilePath, const EncryptionConfig& config, veil::vtl0::logger::logger& veilLog)
{
    try
    {
        CreateEncryptionKeyOnFirstRun(enclave, keyFilePath, config);
        std::wcout << L"User-bound key created and saved to: " << keyFilePath << std::endl;
        veilLog.AddTimestampedLog(L"[Host] User-bound key created successfully", veil::any::logger::eventLevel::EVENT_LEVEL_INFO);
    }
    catch (...)
    {
        std::wcout << L"Error: Failed to create user-bound key." << std::endl;
        throw;
    }
}

bool LoadUBKey(const fs::path& keyFilePath, veil::vtl0::logger::logger& veilLog)
{
    if (fs::exists(keyFilePath))
    {
        std::wcout << L"User-bound key loaded from: " << keyFilePath << std::endl;
        veilLog.AddTimestampedLog(L"[Host] User-bound key loaded successfully", veil::any::logger::eventLevel::EVENT_LEVEL_INFO);
        return true;
    }
    else
    {
        std::wcout << L"Warning: User-bound key file not found at: " << keyFilePath << std::endl;
        return false;
    }
}

void DeleteUBKey(const fs::path& keyFilePath, veil::vtl0::logger::logger& veilLog)
{
    if (fs::exists(keyFilePath))
    {
        fs::remove(keyFilePath);
        std::wcout << L"User-bound key deleted from: " << keyFilePath << std::endl;
        veilLog.AddTimestampedLog(L"[Host] User-bound key deleted successfully", veil::any::logger::eventLevel::EVENT_LEVEL_INFO);
    }
    else
    {
        std::wcout << L"Warning: User-bound key file not found at: " << keyFilePath << std::endl;
    }
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
        // Call the GetSecureId API directly on the static class
        auto secureIdBuffer = [&] () -> IBuffer
        {
            if constexpr (CanGetSecureId<KeyCredentialManager>)
            {
                return KeyCredentialManager::GetSecureId();
            }

            throw winrt::hresult_error(E_NOTIMPL, L"GetSecureId not yet available in the Windows SDK.");
        }();

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

    // Track key loading state
    bool isKeyLoaded = false;

    while (true)
    {
        std::cout << "\n*** User-Bound Key Management and Encryption Menu ***\n";
        std::cout << "1. Create UB Key\n";
        std::cout << "2. Load UB Key\n";
        std::cout << "3. Delete UB Key\n";
        std::cout << "4. Encrypt Data\n";
        std::cout << "5. Decrypt Data\n";
        std::cout << "6. Exit\n";
        std::cout << "Key Status: " << (isKeyLoaded ? "Loaded" : "Not Loaded") << "\n";
        std::cout << "Enter your choice: ";
        
        if (!(std::cin >> choice))
        {
            std::cout << "Invalid input. Please enter a valid option (1-6).\n";
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            continue;
        }

        try
        {
            switch (choice)
            {
                case 1: // Create UB Key
                    CreateUBKey(enclave.get(), keyFilePath, config, veilLog);
                    isKeyLoaded = true;
                    break;

                case 2: // Load UB Key
                    if (!fs::exists(keyFilePath))
                    {
                        std::wcout << L"Error: No user-bound key file found. Please create a key first using option 1." << std::endl;
                        isKeyLoaded = false;
                    }
                    else
                    {
                        isKeyLoaded = LoadUBKey(keyFilePath, veilLog);
                    }
                    break;

                case 3: // Delete UB Key
                    DeleteUBKey(keyFilePath, veilLog);
                    isKeyLoaded = false;
                    break;

                case 4: // Encrypt Data
                    if (!isKeyLoaded && !fs::exists(keyFilePath))
                    {
                        std::wcout << L"No user-bound key available. Creating a new key first..." << std::endl;
                        CreateUBKey(enclave.get(), keyFilePath, config, veilLog);
                        isKeyLoaded = true;
                    }
                    else if (!isKeyLoaded)
                    {
                        std::wcout << L"Loading existing user-bound key..." << std::endl;
                        isKeyLoaded = LoadUBKey(keyFilePath, veilLog);
                    }
                    
                    if (isKeyLoaded)
                    {
                        std::cout << "Enter the string to encrypt: ";
                        std::cin.ignore();
                        std::getline(std::wcin, input);
                        UserBoundEncryptFlow(enclave.get(), input, keyFilePath, encryptedOutputFilePath, config);
                        std::wcout << L"User-bound encryption completed. \nEncrypted bytes saved to: " << encryptedOutputFilePath << std::endl;
                        veilLog.AddTimestampedLog(
                            L"[Host] User-bound encryption completed. Data saved to: " + encryptedOutputFilePath.wstring(),
                            veil::any::logger::eventLevel::EVENT_LEVEL_CRITICAL);
                    }
                    break;

                case 5: // Decrypt Data
                    if (!isKeyLoaded && !fs::exists(keyFilePath))
                    {
                        std::wcout << L"Error: No user-bound key available for decryption." << std::endl;
                        break;
                    }
                    else if (!isKeyLoaded)
                    {
                        std::wcout << L"Loading existing user-bound key..." << std::endl;
                        isKeyLoaded = LoadUBKey(keyFilePath, veilLog);
                    }
                    
                    if (isKeyLoaded)
                    {
                        if (!fs::exists(encryptedOutputFilePath))
                        {
                            std::wcout << L"Error: No encrypted data file found at: " << encryptedOutputFilePath << std::endl;
                            break;
                        }
                        UserBoundDecryptFlow(enclave.get(), keyFilePath, encryptedOutputFilePath, config);
                        std::wcout << L"Note: Key and encrypted data files are preserved for future operations." << std::endl;
                    }
                    break;

                case 6: // Exit
                    std::cout << "Exiting program...\n";
                    return 0;

                default:
                    std::cout << "Invalid choice. Please try again.\n";
            }
        }
        catch (...)
        {
            std::wcout << L"Error: Operation failed. Please try again." << std::endl;
        }
    }
}
