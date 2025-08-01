#pragma once
#pragma once  

#include <windows.h>  
#include <winrt/base.h>

#include <string>  
#include <functional>  
#include <future>  
#include <vector>  

using blob = std::vector<uint8_t>;

// Callback invoked with the challenge. Returns the attestation report.  
//using AuthenticatedSessionChallengeCallback = std::function<blob(const blob& challenge)>;  

enum class KeyCredentialCacheOption
{
    NoCache,
    TimeBased,
    UsageBased,
    TimeAndUsageBased
};

/*
namespace winrt::Windows::Security::Credentials
{
enum class ChallengeResponseKind
{
    VirtualizationBasedSecurityEnclave
};
}

struct KeyCredentialCacheConfiguration
{
    KeyCredentialCacheOption option;
    winrt::Windows::Foundation::TimeSpan timeoutSeconds;
    uint32_t usageCount;

    KeyCredentialCacheConfiguration(
        KeyCredentialCacheOption opt,
        winrt::Windows::Foundation::TimeSpan timeout,
        uint32_t usage)
        : option(opt), timeoutSeconds(timeout), usageCount(usage)
    {
    }
};
*/

// Placeholder types to match usage.  
namespace KeyAlgorithmNames
{
inline const winrt::hstring Ecdh384 = L"ECDSA_P384";
inline const winrt::hstring Ecdh256 = L"ECDSA_P256";
}

enum class KeyCredentialCreationOption {
    ReplaceExisting,
    FailIfExists,
    // Add more as needed  
};

// Represents a key credential (renamed from CreatedCredential).  
class KeyCredential
{
    public:
    blob RetrieveAuthorizationContext() const;
    std::future<std::vector<uint8_t>> RequestDeriveSharedSecretAsync(const std::wstring& message, const std::vector<uint8_t>& ephemeralPublicKeyBytes, HWND windowId) const;
};

// Result of key credential operations containing both the credential and status.
class KeyCredentialRetrievalResult
{
    public:
    KeyCredential credential;
    HRESULT status;

    // Get the credential (only valid if IsSuccess() returns true)
    const KeyCredential& GetCredential() const
    {
        return credential;
    }

    // Get the status code
    HRESULT GetStatus() const noexcept
    {
        return status;
    }
};

namespace winrt::Windows::UI
{
using WindowId = HWND;
}

/*
namespace winrt::Windows::Security::Credentials
{
// Key Credential Manager class with static methods
class KeyCredentialManager
{
    public:
        // Asynchronous function to create a credential and perform authenticated challenge.  
    template <typename AuthenticatedSessionChallengeCallback>
    static std::future<KeyCredentialRetrievalResult> RequestCreateAsync(
        const std::wstring& credentialName,
        KeyCredentialCreationOption creationOption,
        const winrt::hstring& algorithm,
        const std::wstring& message,
        const KeyCredentialCacheConfiguration& cacheConfig,
        HWND windowId,  // Use HWND directly for compatibility  
        winrt::Windows::Security::Credentials::ChallengeResponseKind challengeResponseKind,
        AuthenticatedSessionChallengeCallback&& challengeCallback);

    // Asynchronous function to open a credential and perform authenticated challenge.  
    template <typename AuthenticatedSessionChallengeCallback>
    static std::future<KeyCredentialRetrievalResult> OpenAsync(
        const std::wstring& credentialName,
        winrt::Windows::Security::Credentials::ChallengeResponseKind challengeResponseKind,
        AuthenticatedSessionChallengeCallback&& challengeCallback);
};
}
*/
