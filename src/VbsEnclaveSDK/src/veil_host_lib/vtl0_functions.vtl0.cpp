// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "pch.h"

#include <iostream>
#include <mutex>

#include "utils.vtl0.h"

#include <VbsEnclave\HostApp\Implementation\Untrusted.h>

using namespace veil::vtl0::implementation::debug;

HRESULT veil_abi::Untrusted::Implementation::internal_printf(_In_ const std::string& str)
{
    auto lock = std::scoped_lock<std::mutex>(veil::vtl0::implementation::g_printMutex);

    internal_debug_print("FROM VTL1: " + str);
    return S_OK;
}

HRESULT veil_abi::Untrusted::Implementation::internal_wprintf(_In_ const std::wstring& str)
{
    auto lock = std::scoped_lock<std::mutex>(veil::vtl0::implementation::g_printMutex);

    internal_debug_wprint(L"FROM VTL1: " + str);
    return S_OK;
}

HRESULT veil_abi::Untrusted::Implementation::printf(_In_ const std::string& str)
{
    auto lock = std::scoped_lock<std::mutex>(veil::vtl0::implementation::g_printMutex);

    debug_print("FROM VTL1: " + str);
    return S_OK;
}

HRESULT veil_abi::Untrusted::Implementation::wprintf(_In_ const std::wstring& str)
{
    auto lock = std::scoped_lock<std::mutex>(veil::vtl0::implementation::g_printMutex);

    debug_wprint(L"FROM VTL1: " + str);
    return S_OK;
}
