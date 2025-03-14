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
    const std::filesystem::path& encryptedInputFilePath)
{
    //
    // [Create flow]
    // 
    //  Generate hello-secured key in enclave, then pass the encrypted key bytes vtl0
    //
    
    // Name of a hello key that will be the "root" of our encryption ancestry
    auto helloKeyName = FormatUserHelloKeyName(keyMoniker);

    // Call into enclave
    sample::args::RunHelloSecuredEncryptionKeyExample_CreateEncryptionKey data;
    data.helloKeyName = helloKeyName;
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

    //
    // [Load flow]
    // 
    //  Get (encrypted) key bytes, then pass into enclave to encrypt the input, store the encrypted key and the encrypted bytes to disk
    //
    
    // Call into enclave
    sample::args::RunHelloSecuredEncryptionKeyExample_LoadEncryptionKey loadData;
    loadData.securedEncryptionKeyBytes.data = securedEncryptionKeyBytes.data();
    loadData.securedEncryptionKeyBytes.size = securedEncryptionKeyBytes.size();
    loadData.dataToEncrypt = input;
    loadData.isToBeEncrypted = true;
    THROW_IF_FAILED(veil::vtl0::enclave::call_enclave(enclave, "RunHelloSecuredEncryptionKeyExample_LoadEncryptionKey", loadData));
    auto encryptedInputBytes = std::span<uint8_t>(reinterpret_cast<uint8_t*>(loadData.encryptedInputBytes.data), loadData.encryptedInputBytes.size);

    // Save securedEncryptionKeyBytes to disk
    SaveBinaryData(keyFilePath.string(), securedEncryptionKeyBytes);

    // Save encryptedInputBytes to disk
    SaveBinaryData(encryptedInputFilePath.string(), encryptedInputBytes);

    return 0;
}

int DecryptFlow(
    void* enclave,
    PCWSTR keyMoniker,
    const std::filesystem::path& keyFilePath,
    const std::filesystem::path& encryptedInputFilePath)
{
    //
    // [Load flow]
    // 
    //  Get (encrypted) key bytes from disk, then pass into enclave to decrypt the encrypted input
    //

    auto securedEncryptionKeyBytes = LoadBinaryData(keyFilePath.string());
    auto encryptedInputBytes = LoadBinaryData(encryptedInputFilePath.string());

    // Call into enclave
    sample::args::RunHelloSecuredEncryptionKeyExample_LoadEncryptionKey data;
    data.securedEncryptionKeyBytes.data = securedEncryptionKeyBytes.data();
    data.securedEncryptionKeyBytes.size = securedEncryptionKeyBytes.size();
    data.encryptedInputBytes.data = encryptedInputBytes.data();
    data.encryptedInputBytes.size = encryptedInputBytes.size();
    THROW_IF_FAILED(veil::vtl0::enclave::call_enclave(enclave, "RunHelloSecuredEncryptionKeyExample_LoadEncryptionKey", data));

    auto decryptedInputBytes = std::span<uint8_t>(reinterpret_cast<uint8_t*>(data.decryptedInputBytes.data), data.decryptedInputBytes.size);

    std::wcout << L"Decryption completed in Enclave. Decrypted string: " << decryptedInputBytes.data();

    return 0;
}

int main()
{
    int choice;
    std::wstring input;
    std::wstring encryptedInputFilePath;

    /******************************* Enclave setup *******************************/
    // Create app+user enclave identity
    auto ownerId = veil::vtl0::appmodel::owner_id();

    // Load enclave
    auto flags = ENCLAVE_VBS_FLAG_DEBUG;

    auto enclave = veil::vtl0::enclave::create(ENCLAVE_TYPE_VBS, ownerId, flags, veil::vtl0::enclave::megabytes(512));
    veil::vtl0::enclave::load_image(enclave.get(), L"sample_enclave.dll");
    veil::vtl0::enclave::initialize(enclave.get(), 1);

    // Register framework callbacks
    veil::vtl0::enclave_api::register_callbacks(enclave.get());

    constexpr PCWSTR keyMoniker = L"MyHelloKey-001";

    // File with hello-secured encryption key bytes
    auto keyFilePath = std::filesystem::path(LR"(c:\t\secured_keys)") / keyMoniker;

    do
    {
        std::cout << "\n*** String Encryption and Decryption Menu ***\n";
        std::cout << "1. Encrypt a string\n";
        std::cout << "2. Decrypt a string\n";
        std::cout << "3. Exit\n";
        std::cout << "Enter your choice: ";
        std::cin >> choice;

        // Clear input buffer
        // std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        switch (choice)
        {
            case 1:
                std::cout << "Enter the string to encrypt: ";
                std::getline(std::wcin, input);
                std::wcout << L"Enter the file path to store the encrypted bytes: ";
                std::wcin >> encryptedInputFilePath;
                EncryptFlow(enclave.get(), input, keyMoniker, keyFilePath, encryptedInputFilePath);
                std::wcout << L"Encryption in Enclave completed. Encrypted bytes are saved to disk.";
                break;

            case 2:
                DecryptFlow(enclave.get(), keyMoniker, keyFilePath, encryptedInputFilePath);
                break;

            case 3:
                std::cout << "Exiting program. Goodbye!\n";
                break;

            default:
                std::cout << "Invalid choice. Please try again.\n";
        }
    }
    while (choice != 3);

    std::filesystem::remove(keyFilePath);
    std::filesystem::remove(encryptedInputFilePath);
    return 0;
}
