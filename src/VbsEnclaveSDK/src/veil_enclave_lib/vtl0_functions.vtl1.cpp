// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "pch.h"

#include <VbsEnclave\Enclave\Implementations.h>

namespace veil::vtl1::implementation::vtl0_functions::callouts
{

    HRESULT printf_callback(_In_ const std::string& str)
    {
        RETURN_IF_FAILED(veil_abi::VTL0_Callbacks::printf_callback(str));
        return S_OK;
    }

    HRESULT wprintf_callback(_In_ const std::wstring& str)
    {
        RETURN_IF_FAILED(veil_abi::VTL0_Callbacks::wprintf_callback(str));
        return S_OK;
    }

}
