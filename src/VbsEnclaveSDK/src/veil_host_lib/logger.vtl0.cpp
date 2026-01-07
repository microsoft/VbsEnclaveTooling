// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "pch.h"

#include "logger.vtl0.h"

#include <VbsEnclave\HostApp\Implementation\Untrusted.h>

HRESULT veil_abi::Untrusted::Implementation::add_log(_In_ const std::wstring& log, _In_ const std::wstring& log_file_path)
{
    veil::vtl0::logger::logger::AddTimestampedLog(log, log_file_path);
    return S_OK;
}
