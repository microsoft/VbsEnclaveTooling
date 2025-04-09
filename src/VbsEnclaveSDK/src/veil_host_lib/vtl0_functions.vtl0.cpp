// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "pch.h"

#include <iostream>
#include <mutex>

#include "utils.vtl0.h"

#include <VbsEnclave\HostApp\Stubs.h>

HRESULT veil_abi::VTL0_Stubs::export_interface::printf_callback(_In_ const std::string& str)
{
    auto lock = std::scoped_lock<std::mutex>(veil::vtl0::implementation::g_printMutex);

    std::cout << "FROM VTL1: " << str << std::endl;
    return S_OK;
}

HRESULT veil_abi::VTL0_Stubs::export_interface::wprintf_callback(_In_ const std::wstring& str)
{
    auto lock = std::scoped_lock<std::mutex>(veil::vtl0::implementation::g_printMutex);

    std::wcout << L"FROM VTL1: " << str << std::endl;
    return S_OK;
}
