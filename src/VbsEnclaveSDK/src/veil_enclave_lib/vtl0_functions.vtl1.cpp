// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "pch.h"

#include <VbsEnclave\Enclave\Stubs\Untrusted.h>

namespace veil::vtl1::implementation::vtl0_functions::callouts
{

    HRESULT internal_printf(_In_ const std::string& str)
    {
        RETURN_IF_FAILED(veil_abi::Untrusted::Stubs::internal_printf(str));
        return S_OK;
    }

    HRESULT internal_wprintf(_In_ const std::wstring& str)
    {
        RETURN_IF_FAILED(veil_abi::Untrusted::Stubs::internal_wprintf(str));
        return S_OK;
    }

    HRESULT printf(_In_ const std::string& str)
    {
        RETURN_IF_FAILED(veil_abi::Untrusted::Stubs::printf(str));
        return S_OK;
    }

    HRESULT wprintf(_In_ const std::wstring& str)
    {
        RETURN_IF_FAILED(veil_abi::Untrusted::Stubs::wprintf(str));
        return S_OK;
    }
}
