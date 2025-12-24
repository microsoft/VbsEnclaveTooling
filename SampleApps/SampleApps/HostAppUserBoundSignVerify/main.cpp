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
#include "../Common/user_binding_utils.h"

#include <VbsEnclave\HostApp\Stubs\Trusted.h>

using namespace winrt::Windows::Security::Credentials;
using namespace winrt::Windows::Storage::Streams;

namespace fs = std::filesystem;

constexpr std::wstring_view KEY_NAME = L"MySignatureKey-001";

using SignVerifyConfig = UserBindingConfig<struct SignVerifyConfigTag>;

void CreateAsymmetricKeyOnFirstRun(void* enclave, const fs::path& privateKeyFilePath, const fs::path& publicKeyFilePath, const SignVerifyConfig& config)
{
    auto enclaveInterface = VbsEnclave::Trusted::Stubs::SampleEnclave(enclave);
    THROW_IF_FAILED(enclaveInterface.RegisterVtl0Callbacks());

    auto securedPrivateKeyBytes = std::vector<uint8_t> {};
    auto publicKeyBytes = std::vector<uint8_t> {};

    THROW_IF_FAILED(enclaveInterface.MyEnclaveCreateUserBoundAsymmetricKey(
        config.helloKeyName,
        config.pinMessage,
        reinterpret_cast<uintptr_t>(config.hCurWnd),
        static_cast<uint32_t>(KeyCredentialCreationOption::ReplaceExisting),
        securedPrivateKeyBytes,
        publicKeyBytes));

    SaveBinaryData(privateKeyFilePath, securedPrivateKeyBytes);
    SaveBinaryData(publicKeyFilePath, publicKeyBytes);
    
    std::wcout << L"Asymmetric key pair created successfully!" << std::endl;
    std::wcout << L"Private key (sealed) size: " << securedPrivateKeyBytes.size() << L" bytes" << std::endl;
    std::wcout << L"Public key size: " << publicKeyBytes.size() << L" bytes" << std::endl;
}

void UserBoundSignFlow(
    void* enclave,
    const std::wstring& input,
    const fs::path& privateKeyFilePath,
    const fs::path& signatureOutputFilePath,
    const SignVerifyConfig& config)
{
    auto enclaveInterface = VbsEnclave::Trusted::Stubs::SampleEnclave(enclave);
    THROW_IF_FAILED(enclaveInterface.RegisterVtl0Callbacks());

    auto securedPrivateKeyBytes = LoadBinaryData(privateKeyFilePath);

    auto signatureData = std::vector<uint8_t> {};
    auto resealedPrivateKeyBytes = std::vector<uint8_t> {};
    bool needsReseal = false;    

    THROW_IF_FAILED(enclaveInterface.MyEnclaveLoadUserBoundKeyAndSign(
        config.helloKeyName,
        config.pinMessage,
        reinterpret_cast<uintptr_t>(config.hCurWnd),
        securedPrivateKeyBytes,
        input,
        signatureData,
        needsReseal,
        resealedPrivateKeyBytes
    ));

    if (needsReseal && !resealedPrivateKeyBytes.empty())
    {
        std::wcout << L"Private key needs re-sealing, saving resealed key to disk..." << std::endl;
        std::wcout << L"Resealed key size: " << resealedPrivateKeyBytes.size() << std::endl;
        SaveBinaryData(privateKeyFilePath, resealedPrivateKeyBytes);
    }
    
    SaveBinaryData(signatureOutputFilePath, signatureData);
    std::wcout << L"Data signed successfully! Signature size: " << signatureData.size() << L" bytes" << std::endl;
}

void UserBoundVerifyFlow(
    void* enclave,
    const std::wstring& input,
    const fs::path& publicKeyFilePath,
    const fs::path& signatureInputFilePath,
    const SignVerifyConfig& config)
{
    auto enclaveInterface = VbsEnclave::Trusted::Stubs::SampleEnclave(enclave);
    THROW_IF_FAILED(enclaveInterface.RegisterVtl0Callbacks());

    auto publicKeyBytes = LoadBinaryData(publicKeyFilePath);
    auto signatureData = LoadBinaryData(signatureInputFilePath);

    bool isValid = false;

    THROW_IF_FAILED(enclaveInterface.MyEnclaveVerifySignature(
        publicKeyBytes,
        input,
        signatureData,
        isValid
    ));

    if (isValid)
    {
        std::cout << "[SUCCESS] Signature verification SUCCEEDED! The data is authentic." << std::endl;
        std::cout.flush();
    }
    else
    {
        std::cout << "[FAILED] Signature verification FAILED! The data may have been tampered with." << std::endl;
        std::cout.flush();
    }
}

// Key management helper functions
void CreateKeyPair(void* enclave, const fs::path& privateKeyFilePath, const fs::path& publicKeyFilePath, const SignVerifyConfig& config, veil::vtl0::logger::logger& veilLog)
{
    try
    {
        CreateAsymmetricKeyOnFirstRun(enclave, privateKeyFilePath, publicKeyFilePath, config);
        std::wcout << L"User-bound asymmetric key pair created and saved" << std::endl;
        std::wcout << L"Private key (sealed): " << privateKeyFilePath << std::endl;
        std::wcout << L"Public key: " << publicKeyFilePath << std::endl;
        veilLog.AddTimestampedLog(L"[Host] User-bound key pair created successfully", veil::any::logger::eventLevel::EVENT_LEVEL_INFO);
    }
    catch (...)
    {
        std::wcout << L"Error: Failed to create user-bound key pair." << std::endl;
        throw;
    }
}

bool LoadKeyPair(const fs::path& privateKeyFilePath, const fs::path& publicKeyFilePath, veil::vtl0::logger::logger& veilLog)
{
    if (fs::exists(privateKeyFilePath) && fs::exists(publicKeyFilePath))
    {
        std::wcout << L"User-bound key pair loaded from:" << std::endl;
        std::wcout << L"  Private key: " << privateKeyFilePath << std::endl;
        std::wcout << L"  Public key: " << publicKeyFilePath << std::endl;
        veilLog.AddTimestampedLog(L"[Host] User-bound key pair loaded successfully", veil::any::logger::eventLevel::EVENT_LEVEL_INFO);
        return true;
    }
    else
    {
        std::wcout << L"Warning: User-bound key pair files not found." << std::endl;
        return false;
    }
}

void DeleteKeyPair(const fs::path& privateKeyFilePath, const fs::path& publicKeyFilePath, veil::vtl0::logger::logger& veilLog)
{
    bool deletedAny = false;
    if (fs::exists(privateKeyFilePath))
    {
        fs::remove(privateKeyFilePath);
        std::wcout << L"Private key deleted from: " << privateKeyFilePath << std::endl;
        deletedAny = true;
    }
    if (fs::exists(publicKeyFilePath))
    {
        fs::remove(publicKeyFilePath);
        std::wcout << L"Public key deleted from: " << publicKeyFilePath << std::endl;
        deletedAny = true;
    }
    
    if (deletedAny)
    {
        veilLog.AddTimestampedLog(L"[Host] User-bound key pair deleted successfully", veil::any::logger::eventLevel::EVENT_LEVEL_INFO);
    }
    else
    {
        std::wcout << L"Warning: No key files found to delete." << std::endl;
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
    const fs::path keyDirPath = fs::current_path();
    const fs::path signatureOutputFilePath = keyDirPath / "signature_userbound";

    bool areUserBindingApisAvailable;
    auto config = InitializeUserBindingConfig<SignVerifyConfig>(
        KEY_NAME,
        L"Please enter your PIN to access the signature key.",
        areUserBindingApisAvailable);

    if (!EnsureUserBindingApisAvailable(areUserBindingApisAvailable))
    {
        std::cout << "\nPress any key to exit..." << std::endl;
        _getch();
        return 1;
    }

    veil::vtl0::logger::logger veilLog(
        L"HostAppUserBoundSignVerify",
        L"C3D4E5F6-7890-1234-CDEF-345678901235",
        static_cast<veil::any::logger::eventLevel>(activityLevel));

    veilLog.AddTimestampedLog(L"[Host] Starting user-bound sign/verify from host", veil::any::logger::eventLevel::EVENT_LEVEL_CRITICAL);

    std::vector<uint8_t> ownerId;

    try
    {
        ownerId = GetSecureIdFromWindowsHello();
    }
    catch (...)
    {
        std::wcout << L"Cannot proceed without a valid secure ID for user-bound operations." << std::endl;
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
    auto privateKeyFilePath = keyDirPath / (std::wstring(keyMoniker) + L"_private");
    auto publicKeyFilePath = keyDirPath / (std::wstring(keyMoniker) + L"_public");

    // Track key loading state
    bool isKeyLoaded = false;

    while (true)
    {
        std::cout << "\n*** User-Bound Asymmetric Key Sign/Verify Menu ***\n";
        std::cout << "1. Create Key Pair (Private + Public)\n";
        std::cout << "2. Load Key Pair\n";
        std::cout << "3. Delete Key Pair\n";
        std::cout << "4. Sign Data (requires Windows Hello)\n";
        std::cout << "5. Verify Signature (no Windows Hello)\n";
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
                case 1: // Create Key Pair
                    CreateKeyPair(enclave.get(), privateKeyFilePath, publicKeyFilePath, config, veilLog);
                    isKeyLoaded = true;
                    break;

                case 2: // Load Key Pair
                    if (!fs::exists(privateKeyFilePath) || !fs::exists(publicKeyFilePath))
                    {
                        std::wcout << L"Error: Key pair files not found. Please create keys first using option 1." << std::endl;
                        isKeyLoaded = false;
                    }
                    else
                    {
                        isKeyLoaded = LoadKeyPair(privateKeyFilePath, publicKeyFilePath, veilLog);
                    }
                    break;

                case 3: // Delete Key Pair
                    DeleteKeyPair(privateKeyFilePath, publicKeyFilePath, veilLog);
                    isKeyLoaded = false;
                    break;

                case 4: // Sign Data
                    if (!isKeyLoaded && (!fs::exists(privateKeyFilePath) || !fs::exists(publicKeyFilePath)))
                    {
                        std::wcout << L"No key pair available. Creating a new key pair first..." << std::endl;
                        CreateKeyPair(enclave.get(), privateKeyFilePath, publicKeyFilePath, config, veilLog);
                        isKeyLoaded = true;
                    }
                    else if (!isKeyLoaded)
                    {
                        std::wcout << L"Loading existing key pair..." << std::endl;
                        isKeyLoaded = LoadKeyPair(privateKeyFilePath, publicKeyFilePath, veilLog);
                    }
                    
                    if (isKeyLoaded)
                    {
                        std::cout << "Enter the string to sign: ";
                        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                        std::getline(std::wcin, input);
                        
                        std::cout << "\n*** Windows Hello prompt will appear to access private key ***" << std::endl;
                        UserBoundSignFlow(enclave.get(), input, privateKeyFilePath, signatureOutputFilePath, config);
                        std::wcout << L"Signature saved to: " << signatureOutputFilePath << std::endl;
                        std::cout.flush();
                        veilLog.AddTimestampedLog(
                            L"[Host] User-bound signing completed. Signature saved to: " + signatureOutputFilePath.wstring(),
                            veil::any::logger::eventLevel::EVENT_LEVEL_CRITICAL);
                    }
                    break;

                case 5: // Verify Signature
                    if (!isKeyLoaded && (!fs::exists(privateKeyFilePath) || !fs::exists(publicKeyFilePath)))
                    {
                        std::wcout << L"Error: No key pair available for verification." << std::endl;
                        break;
                    }
                    else if (!isKeyLoaded)
                    {
                        std::wcout << L"Loading existing key pair..." << std::endl;
                        isKeyLoaded = LoadKeyPair(privateKeyFilePath, publicKeyFilePath, veilLog);
                    }
                    
                    if (isKeyLoaded)
                    {
                        if (!fs::exists(signatureOutputFilePath))
                        {
                            std::wcout << L"Error: No signature file found at: " << signatureOutputFilePath << std::endl;
                            std::wcout << L"Please sign data first using option 4." << std::endl;
                            break;
                        }
                        
                        std::cout << "Enter the string to verify (must match the signed data): ";
                        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
                        std::getline(std::wcin, input);
                        
                        std::cout << "\n*** No Windows Hello prompt - using public key only ***" << std::endl;
                        std::cout << "Starting verification..." << std::endl;
                        std::cout.flush();
                        UserBoundVerifyFlow(enclave.get(), input, publicKeyFilePath, signatureOutputFilePath, config);
                        std::cout << "Verification completed." << std::endl;
                        veilLog.AddTimestampedLog(
                            L"[Host] Signature verification completed",
                            veil::any::logger::eventLevel::EVENT_LEVEL_CRITICAL);
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
