// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "pch.h"

#include "logger.vtl1.h"

#include <VbsEnclave\Enclave\Stubs\Untrusted.h>

namespace veil::vtl1::logger::implementation::callouts
{
    void add_log(std::wstring_view log, std::wstring_view logFilePath)
    {
        THROW_IF_FAILED(veil_abi::Untrusted::Stubs::add_log({log.data()}, {logFilePath.data()}));
    }
}


