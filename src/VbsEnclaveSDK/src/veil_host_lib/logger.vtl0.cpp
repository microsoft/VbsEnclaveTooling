// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "pch.h"

#include "logger.vtl0.h"

#include <VbsEnclave\HostApp\Stubs.h>

namespace veil::vtl0::logger
{
    std::mutex logMutex;
}

HRESULT veil_abi::VTL0_Stubs::export_interface::add_log_callback(_In_ const std::wstring& log, _In_ const std::wstring& log_file_path)
{
    veil::vtl0::logger::logger::AddTimestampedLog(log, log_file_path);
    return S_OK;
}
