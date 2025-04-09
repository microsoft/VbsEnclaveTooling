// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "pch.h"

#include "logger.vtl1.h"

#include <VbsEnclave\Enclave\Implementations.h>

namespace veil::vtl1::logger::implementation::callouts
{
    void add_log(std::wstring_view log, std::wstring_view logFilePath)
    {
        THROW_IF_FAILED(veil_abi::VTL0_Callbacks::add_log_callback({log.data()}, {logFilePath.data()}));
    }
}


