#pragma once

#include <functional>
#include <future>
#include <string>
#include <tuple>
#include <vector>
#include <memory>
#include <iostream>

// Include Windows headers first to define basic types
#include <windows.h>
#include <ntenclv.h>
#include <enclaveium.h>
#include <roapi.h>
#include <winstring.h>
#include <unknwn.h>  // For IUnknown interface

#include <winrt/base.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Security.Credentials.h>
#include <winrt/Windows.Security.Cryptography.h>
#include <winrt/Windows.Security.Cryptography.Certificates.h>
#include <winrt/Windows.Storage.Streams.h>

#include <VbsEnclave\HostApp\Stubs.h>
#include "..\veil_enclave_lib\vengcdll.h"
// #include <veinterop_kcm.h>
#include <VbsEnclave\HostApp\DeveloperTypes.h>
#include <sddl.h>

using namespace winrt::Windows::Security::Credentials;

// Helper function to convert WinRT IBuffer to std::vector<uint8_t>
std::vector<uint8_t> ConvertBufferToVector(winrt::Windows::Storage::Streams::IBuffer const& buffer)
{
    winrt::com_array<uint8_t> byteArray;
    winrt::Windows::Security::Cryptography::CryptographicBuffer::CopyToByteArray(buffer, byteArray);
    return std::vector<uint8_t>(byteArray.begin(), byteArray.end());
}

std::wstring FormatUserHelloKeyName(PCWSTR name)
{
    static constexpr wchar_t c_formatString[] = L"{}//{}//{}";
    HANDLE tokenHandle = nullptr;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tokenHandle))
    {
        // Handle error
        return {};
    }

    DWORD tokenInfoLength = 0;
    GetTokenInformation(tokenHandle, TokenUser, nullptr, 0, &tokenInfoLength);
    std::vector<BYTE> tokenInfoBuffer(tokenInfoLength);

    if (!GetTokenInformation(tokenHandle, TokenUser, tokenInfoBuffer.data(), tokenInfoLength, &tokenInfoLength))
    {
        // Handle error
        CloseHandle(tokenHandle);
        return {};
    }

    PTOKEN_USER tokenUser = reinterpret_cast<PTOKEN_USER>(tokenInfoBuffer.data());

    // Extract the SID from the TOKEN_USER structure
    PSID userSid = tokenUser->User.Sid;  // This is how you get the SID

    // Convert SID to string
    LPWSTR userSidString = nullptr;
    if (!ConvertSidToStringSidW(userSid, &userSidString))
    {
        // Handle error
        CloseHandle(tokenHandle);
        return {};
    }

    CloseHandle(tokenHandle);

    // Create the formatted key name
    std::wstring result = std::format(c_formatString, userSidString, userSidString, name);

    // Free the SID string allocated by ConvertSidToStringSidW
    LocalFree(userSidString);

    return result;
}

winrt::hstring GetAlgorithm(uintptr_t ecdhAlgorithm)
{
    using namespace winrt::Windows::Security::Cryptography::Certificates;
    if (reinterpret_cast<BCRYPT_ALG_HANDLE>(ecdhAlgorithm) == BCRYPT_ECDH_P384_ALG_HANDLE)
    {
        return KeyAlgorithmNames::Ecdh384();
    }
    else if (reinterpret_cast<BCRYPT_ALG_HANDLE>(ecdhAlgorithm) == BCRYPT_ECDH_P256_ALG_HANDLE)
    {
        return KeyAlgorithmNames::Ecdh256();
    }
    THROW_HR(E_INVALIDARG);
}

// Helper function to convert DeveloperTypes::keyCredentialCacheConfig to KeyCredentialCacheConfiguration
KeyCredentialCacheConfiguration ConvertCacheConfig(const DeveloperTypes::keyCredentialCacheConfig& cacheConfig)
{
    // Map cacheOption to KeyCredentialCacheOption
    KeyCredentialCacheOption cacheOption;
    switch (cacheConfig.cacheOption)
    {
        case 0:
            cacheOption = KeyCredentialCacheOption::NoCache;
            break;
        case 1:
            cacheOption = KeyCredentialCacheOption::CacheWhenUnlocked;
            break;
        default:
            cacheOption = KeyCredentialCacheOption::NoCache; // Default fallback
            break;
    }

    // Convert timeout from seconds to TimeSpan (100-nanosecond units)
    winrt::Windows::Foundation::TimeSpan timeout{ static_cast<int64_t>(cacheConfig.cacheTimeoutInSeconds) * 10000000LL };

    // Use RoGetActivationFactory to get the factory for KeyCredentialCacheConfiguration
    winrt::com_ptr<winrt::Windows::Security::Credentials::IKeyCredentialCacheConfigurationFactory> factory;

    // Create HSTRING for the runtime class name
    winrt::hstring className = L"Windows.Security.Credentials.KeyCredentialCacheConfiguration";

    // Get the activation factory using RoGetActivationFactory
    HRESULT hr = RoGetActivationFactory(
        reinterpret_cast<HSTRING>(winrt::get_abi(className)),
        winrt::guid_of<winrt::Windows::Security::Credentials::IKeyCredentialCacheConfigurationFactory>(),
        factory.put_void());

    if (SUCCEEDED(hr))
    {
        winrt::com_ptr<winrt::Windows::Security::Credentials::IKeyCredentialCacheConfiguration> instance;
        hr = factory->CreateInstance(
            static_cast<int32_t>(cacheOption),
            winrt::get_abi(timeout),
            cacheConfig.cacheUsageCount,
            reinterpret_cast<void**>(instance.put()));

        return winrt::Windows::Security::Credentials::KeyCredentialCacheConfiguration {
                    instance.detach(), winrt::take_ownership_from_abi
        };
    }

    // If RoGetActivationFactory fails, throw an exception
    THROW_HR(hr);

}

authContextBlobAndFormattedKeyNameAndSessionInfo veil_abi::VTL0_Stubs::export_interface::userboundkey_establish_session_for_create_callback(
    uintptr_t enclave,
    const std::wstring& key_name,
    uintptr_t ecdh_protocol,
    const std::wstring& message,
    uintptr_t window_id,
    const DeveloperTypes::keyCredentialCacheConfig& cache_config,
    uint64_t nonce)
{
    std::wcout << L"Inside userboundkey_establish_session_for_create_callback"<< std::endl;
    auto algorithm = GetAlgorithm(ecdh_protocol);

    // Convert the cacheConfig parameter to KeyCredentialCacheConfiguration
    auto cacheConfiguration = ConvertCacheConfig(cache_config);

    auto sessionKeyPtr = std::make_shared<uintptr_t>(0);
    auto enclaveptr = (void*)enclave;
    
    // Create the enclave interface directly with the VBS enclave handle
    // The VBS Enclave framework will handle the module resolution internally
    auto enclaveInterface = veil_abi::VTL0_Stubs::export_interface(enclaveptr);

    std::wcout << L"DEBUG: Registering VTL0 callbacks..." << std::endl;
    HRESULT hr = enclaveInterface.RegisterVtl0Callbacks();
    if (FAILED(hr))
    {
        std::wcout << L"DEBUG: RegisterVtl0Callbacks failed with HRESULT: 0x" << std::hex << hr << std::endl;
        THROW_HR(hr);
    }
    std::wcout << L"DEBUG: VTL0 callbacks registered successfully!" << std::endl;
    
    
    std::wcout << L"Calling RequestCreateAsync" << std::endl;
    auto credentialResult = KeyCredentialManager::RequestCreateAsync(
        key_name,
        KeyCredentialCreationOption::ReplaceExisting,
        algorithm,
        message,
        cacheConfiguration,
        (winrt::Windows::UI::WindowId)window_id,
        ChallengeResponseKind::VirtualizationBasedSecurityEnclave,
        [sessionKeyPtr, enclaveptr] (const auto& challenge) mutable -> winrt::Windows::Storage::Streams::IBuffer
        {            
            std::wcout << L"DEBUG: Challenge callback invoked! Challenge size: " << challenge.Length() << std::endl;
            
            try {
                auto enclaveInterface = veil_abi::VTL0_Stubs::export_interface(enclaveptr);

                std::wcout << L"DEBUG: Registering VTL0 callbacks inside lambda..." << std::endl;
                HRESULT hr = enclaveInterface.RegisterVtl0Callbacks();
                if (FAILED(hr)) {
                    std::wcout << L"DEBUG: RegisterVtl0Callbacks failed inside lambda with HRESULT: 0x" << std::hex << hr << std::endl;
                    THROW_HR(hr);
                }
                std::wcout << L"DEBUG: VTL0 callbacks registered successfully inside lambda!" << std::endl;

                std::wcout << L"DEBUG: Converting challenge buffer..." << std::endl;
                auto challengeVector = ConvertBufferToVector(challenge);
                std::wcout << L"DEBUG: Challenge vector size: " << challengeVector.size() << std::endl;

                std::wcout << L"DEBUG: About to call userboundkey_get_attestation_report..." << std::endl;
                auto attestationReportAndSessionKeyPtr = enclaveInterface.userboundkey_get_attestation_report(challengeVector);
                std::wcout << L"DEBUG: userboundkey_get_attestation_report returned successfully!" << std::endl;

                *sessionKeyPtr = attestationReportAndSessionKeyPtr.sessionKeyPtr;
                std::wcout << L"DEBUG: Session key stored: " << *sessionKeyPtr << std::endl;
            
                // Convert std::vector<uint8_t> back to IBuffer for return
                std::wcout << L"DEBUG: Converting attestation report back to IBuffer..." << std::endl;
                auto result = winrt::Windows::Security::Cryptography::CryptographicBuffer::CreateFromByteArray(attestationReportAndSessionKeyPtr.attestationReport);
                std::wcout << L"DEBUG: Challenge callback completed successfully!" << std::endl;
                return result;
            }
            catch (const std::exception& e) {
                std::wcout << L"DEBUG: Exception in challenge callback: " << e.what() << std::endl;
                throw;
            }
            catch (...) {
                std::wcout << L"DEBUG: Unknown exception in challenge callback!" << std::endl;
                throw;
            }
        }
    ).get();

    std::wcout << L"RequestCreateAsync returned" << std::endl;

    // Check if the operation was successful
    auto status = credentialResult.Status();
    if (status != KeyCredentialStatus::Success)
    {
        THROW_HR(static_cast<HRESULT>(status));
    }

    const auto& credential = credentialResult.Credential();
    std::wstring formattedKeyName = FormatUserHelloKeyName(key_name.c_str());

    authContextBlobAndFormattedKeyNameAndSessionInfo result;

    winrt::Windows::Storage::Streams::IBuffer encryptedRequest;
    auto authContextBuffer = credential.RetrieveAuthorizationContext(encryptedRequest);
    result.authContextBlob = ConvertBufferToVector(authContextBuffer);
    result.formattedKeyName = formattedKeyName; // Store the formatted key name
    result.session = {*sessionKeyPtr, nonce}; // Initialize session info

    return result;
}

// Helper function to validate that a COM object is still valid
bool IsValidCOMObject(void* abi)
{
    if (abi == nullptr)
        return false;
    
    try
    {
        // Try to QueryInterface for IUnknown - this will fail if the object is invalid
        IUnknown* unknown = nullptr;
        HRESULT hr = static_cast<IUnknown*>(abi)->QueryInterface(IID_IUnknown, reinterpret_cast<void**>(&unknown));
        if (SUCCEEDED(hr) && unknown != nullptr)
        {
            unknown->Release(); // Release the extra reference from QueryInterface
            return true;
        }
    }
    catch (...)
    {
        // Any exception means the object is invalid
        return false;
    }
    
    return false;
}

// Helper function to convert a KeyCredential to vector<uint8_t> for transmission to VTL1
std::vector<uint8_t> ConvertCredentialToVector(const KeyCredential& credential)
{
    // Get the ABI pointer and AddRef to keep the COM object alive
    auto abi = winrt::get_abi(credential);
    
    // Validate the COM object before proceeding
    if (!IsValidCOMObject(abi))
    {
        std::wcout << L"ERROR: ConvertCredentialToVector - Invalid COM object" << std::endl;
        THROW_HR(E_INVALIDARG);
    }
    
    static_cast<IUnknown*>(abi)->AddRef(); // Increment reference count to keep object alive
    
    std::wcout << L"DEBUG: ConvertCredentialToVector - AddRef called on credential ABI: 0x" << std::hex << reinterpret_cast<uintptr_t>(abi) << std::dec << std::endl;
    
    uintptr_t credentialPtr = reinterpret_cast<uintptr_t>(abi);
    std::vector<uint8_t> credentialVector(sizeof(uintptr_t));
    memcpy(credentialVector.data(), &credentialPtr, sizeof(uintptr_t));
    return credentialVector;
}

// Helper function to convert vector<uint8_t> back to KeyCredential
KeyCredential ConvertVectorToCredential(const std::vector<uint8_t>& credentialVector)
{
    if (credentialVector.size() != sizeof(uintptr_t))
    {
        THROW_HR(E_INVALIDARG);
    }
    
    uintptr_t credentialPtr;
    memcpy(&credentialPtr, credentialVector.data(), sizeof(uintptr_t));
    void* abi = reinterpret_cast<void*>(credentialPtr);
    
    std::wcout << L"DEBUG: ConvertVectorToCredential - Retrieved credential ABI: 0x" << std::hex << credentialPtr << std::dec << std::endl;
    
    // Validate the COM object before creating the KeyCredential
    if (!IsValidCOMObject(abi))
    {
        std::wcout << L"ERROR: ConvertVectorToCredential - Invalid COM object, likely destroyed" << std::endl;
        THROW_HR(E_INVALIDARG);
    }
    
    // Create KeyCredential and transfer ownership (this will handle the Release)
    // The take_ownership_from_abi will NOT AddRef, so our earlier AddRef is consumed
    return KeyCredential{ abi, winrt::take_ownership_from_abi };
}

credentialAndFormattedKeyNameAndSessionInfo veil_abi::VTL0_Stubs::export_interface::userboundkey_establish_session_for_load_callback(
    uintptr_t enclave,
    const std::wstring& key_name,
    const std::wstring& message,
    uintptr_t window_id,
    uint64_t nonce)
{
    auto sessionKeyPtr = std::make_shared<uintptr_t>(0);

    auto enclaveptr = (void*)enclave;
    auto enclaveInterface = veil_abi::VTL0_Stubs::export_interface(enclaveptr);
    HRESULT hr = enclaveInterface.RegisterVtl0Callbacks();
    if (FAILED(hr))
    {
        std::wcout << L"DEBUG: RegisterVtl0Callbacks failed inside lambda with HRESULT: 0x" << std::hex << hr << std::endl;
        THROW_HR(hr);
    }
    std::wcout << L"DEBUG: VTL0 callbacks registered successfully inside lambda!" << std::endl;

    auto credentialResult = KeyCredentialManager::OpenAsync(
        key_name.c_str(),
        ChallengeResponseKind::VirtualizationBasedSecurityEnclave,
        [sessionKeyPtr, enclaveptr] (const auto& challenge) mutable -> winrt::Windows::Storage::Streams::IBuffer
    {
        std::wcout << L"DEBUG: Load callback challenge invoked! Challenge size: " << challenge.Length() << std::endl;
        
        try {
            auto enclaveInterface = veil_abi::VTL0_Stubs::export_interface(enclaveptr);
            HRESULT hr = enclaveInterface.RegisterVtl0Callbacks();
            if (FAILED(hr)) {
                std::wcout << L"DEBUG: RegisterVtl0Callbacks failed inside lambda with HRESULT: 0x" << std::hex << hr << std::endl;
                THROW_HR(hr);
            }
            std::wcout << L"DEBUG: VTL0 callbacks registered successfully inside lambda!" << std::endl;

            std::wcout << L"DEBUG: Converting challenge buffer..." << std::endl;
            auto challengeVector = ConvertBufferToVector(challenge);
            std::wcout << L"DEBUG: Challenge vector size: " << challengeVector.size() << std::endl;

            std::wcout << L"DEBUG: About to call userboundkey_get_attestation_report (load callback)..." << std::endl;
            auto attestationReportAndSessionKeyPtr = enclaveInterface.userboundkey_get_attestation_report(challengeVector);
            std::wcout << L"DEBUG: userboundkey_get_attestation_report returned successfully (load callback)!" << std::endl;
            
            *sessionKeyPtr = attestationReportAndSessionKeyPtr.sessionKeyPtr;
            
            // Convert std::vector<uint8_t> back to IBuffer for return
            return winrt::Windows::Security::Cryptography::CryptographicBuffer::CreateFromByteArray(attestationReportAndSessionKeyPtr.attestationReport);
        }
        catch (const std::exception& e) {
            std::wcout << L"DEBUG: Exception in load callback: " << e.what() << std::endl;
            throw;
        }
        catch (...) {
            std::wcout << L"DEBUG: Unknown exception in load callback!" << std::endl;
            throw;
        }
    }
    ).get();

    // Check if the operation was successful
    auto status = credentialResult.Status();
    if (status != KeyCredentialStatus::Success)
    {
        THROW_HR(static_cast<HRESULT>(status));
    }

    const auto& credential = credentialResult.Credential();
    std::wstring formattedKeyName = FormatUserHelloKeyName(key_name.c_str());

    // Return the credential as a vector along with sessionKeyPtr for VTL1 to use later
    credentialAndFormattedKeyNameAndSessionInfo result;
    result.credential = ConvertCredentialToVector(credential);
    result.formattedKeyName = formattedKeyName;
    result.session = { *sessionKeyPtr, nonce }; // Initialize session info
    return result;
}

// New VTL0 function to extract authorization context from credential
std::vector<uint8_t> veil_abi::VTL0_Stubs::export_interface::userboundkey_get_authorization_context_from_credential_callback(
    const std::vector<uint8_t>& credential_vector,
    const std::vector<uint8_t>& encrypted_kcm_request_for_get_authorization_context,
    const std::wstring& message,
    uintptr_t window_id)
{
    std::wcout << L"DEBUG: userboundkey_get_authorization_context_from_credential_callback called" << std::endl;

    KeyCredential credential{ nullptr };
    bool credentialValid = false;
    
    try
    {
        // Convert the credential vector back to KeyCredential
        credential = ConvertVectorToCredential(credential_vector);
        credentialValid = true;
        
        std::wcout << L"DEBUG: Converting credential vector back to KeyCredential" << std::endl;

        // Extract authorization context
        auto authorizationContext = credential.RetrieveAuthorizationContext(
            winrt::Windows::Security::Cryptography::CryptographicBuffer::CreateFromByteArray(encrypted_kcm_request_for_get_authorization_context));

        auto result = ConvertBufferToVector(authorizationContext);

        std::wcout << L"DEBUG: userboundkey_get_authorization_context_from_credential_callback completed successfully" << std::endl;
        
        // The KeyCredential destructor will automatically handle the Release when it goes out of scope
        return result;
    }
    catch (const std::exception& e)
    {
        std::wcout << L"DEBUG: Exception in userboundkey_get_authorization_context_from_credential_callback: " << e.what() << std::endl;

        // If we successfully created the credential but failed later, the destructor will clean up
        // If we failed to create the credential, there's nothing extra to clean up
        throw;
    }
    catch (...)
    {
        std::wcout << L"DEBUG: Unknown exception in userboundkey_get_authorization_context_from_credential_callback" << std::endl;
        
        // If we successfully created the credential but failed later, the destructor will clean up
        // If we failed to create the credential, there's nothing extra to clean up
        throw;
    }
}

// New VTL0 function to extract secret from credential
std::vector<uint8_t> veil_abi::VTL0_Stubs::export_interface::userboundkey_get_secret_from_credential_callback(
    const std::vector<uint8_t>& credential_vector,
    const std::vector<uint8_t>& encrypted_kcm_request_for_derive_shared_secret,
    const std::wstring& message,
    uintptr_t window_id)
{
    std::wcout << L"DEBUG: userboundkey_get_secret_from_credential_callback called" << std::endl;

    KeyCredential credential {nullptr};
    bool credentialValid = false;

    try
    {
        // Convert the credential vector back to KeyCredential
        credential = ConvertVectorToCredential(credential_vector);
        credentialValid = true;

        std::wcout << L"DEBUG: Converting credential vector back to KeyCredential" << std::endl;

        // Derive shared secret
        auto secret = credential.RequestDeriveSharedSecretAsync(
            (winrt::Windows::UI::WindowId)window_id,
            message,
            winrt::Windows::Security::Cryptography::CryptographicBuffer::CreateFromByteArray(encrypted_kcm_request_for_derive_shared_secret)).get();

        auto result = ConvertBufferToVector(secret.Result());
        std::wcout << L"DEBUG: userboundkey_get_secret_from_credential_callback completed successfully" << std::endl;

        // The KeyCredential destructor will automatically handle the Release when it goes out of scope
        return result;
    }
    catch (const std::exception& e)
    {
        std::wcout << L"DEBUG: Exception in userboundkey_get_secret_from_credential_callback: " << e.what() << std::endl;

        // If we successfully created the credential but failed later, the destructor will clean up
        // If we failed to create the credential, there's nothing extra to clean up
        throw;
    }
    catch (...)
    {
        std::wcout << L"DEBUG: Unknown exception in userboundkey_get_secret_from_credential_callback" << std::endl;

        // If we successfully created the credential but failed later, the destructor will clean up
        // If we failed to create the credential, there's nothing extra to clean up
        throw;
    }
}
