// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <string>
#include <filesystem>
#include <iostream>

#include <windows.h>
#include <winrt/base.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Foundation.Metadata.h>
#include <winrt/Windows.Security.Credentials.h>
#include <winrt/Windows.Storage.Streams.h>

using namespace winrt::Windows::Security::Credentials;
using namespace winrt::Windows::Storage::Streams;

namespace fs = std::filesystem;

// Generic config structure for user-bound operations
template<typename ConfigType>
struct UserBindingConfig
{
    std::wstring helloKeyName;
    std::wstring pinMessage;
    HWND hCurWnd;
};

// Template concept to check for GetSecureId availability
template <typename T>
concept CanGetSecureId =
    requires { { T::GetSecureId() }; };

// Initialize user binding configuration and check API availability
template<typename ConfigType>
inline ConfigType InitializeUserBindingConfig(
    const std::wstring_view& keyName,
    const std::wstring& pinMessage,
    bool& areUserBindingApisAvailable)
{
    ConfigType config;
    config.helloKeyName = keyName;
    config.pinMessage = pinMessage;
    
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

// Check if a key file exists and is loaded
inline bool IsKeyFileLoaded(const fs::path& keyFilePath)
{
    return fs::exists(keyFilePath);
}

// Get secure ID from Windows Hello
inline std::vector<uint8_t> GetSecureIdFromWindowsHello()
{
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
        throw;
    }
    catch (...)
    {
        std::wcout << L"Error: Exception occurred while getting secure ID." << std::endl;
        throw;
    }
    
    return ownerId;
}

// Ensure user binding APIs are available before proceeding
inline bool EnsureUserBindingApisAvailable(bool areUserBindingApisAvailable)
{
    if (!areUserBindingApisAvailable)
    {
        std::wcout << L"Error: User Binding APIs are not available on this system." << std::endl;
        std::wcout << L"This feature requires Windows Hello and appropriate hardware support." << std::endl;
        return false;
    }
    return true;
}
