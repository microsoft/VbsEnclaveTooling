// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "pch.h"
#include <mutex>
#include <winrt/Windows.Security.Credentials.h>
#include <winrt/Windows.Storage.Streams.h>

namespace veil::vtl0::implementation
{
    extern std::mutex g_printMutex;
}

namespace veil::vtl0::internal::utils
{
    using namespace winrt::Windows::Storage::Streams;
    using namespace winrt::Windows::Security::Credentials;

    inline IBuffer GetAuthorizationContext(KeyCredential& credential, IBuffer& encryptedBuffer)
    {
        #ifdef _VEINTEROP_KCM_
        {
            return credential.RetrieveAuthorizationContext(encryptedBuffer);
        }
        #else
        {
            // The presence of _VEINTEROP_KCM_ should indicate that the official veinterop_kcm APIs
            // are available. This should mean that the updates to the KCM APIs are available as well.
            throw wil::ResultException(E_NOTIMPL);
        }
        #endif
    }
}
