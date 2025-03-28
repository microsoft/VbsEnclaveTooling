// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "pch.h"

#include <format>

#include <gsl/gsl_util>

#include <sddl.h>

#include "telemetry.any.h"
#include "utils.any.h"

#include "hello.vtl0.h"

namespace simplified
{
    static void add_log(veil::any::implementation::args::add_log* data)
    {
        __debugbreak();
        auto tempData = data->log;

        // veil::any::telemetry::AddLog(data->log, data->logLevel);
        std::filesystem::path filePath(L"C:\\testLog.txt");
        std::wofstream wofs(filePath, std::ios::out | std::ios::app);
        wofs << data->log << std::flush;
        wofs.close();
    }
}

namespace veil::vtl0::implementation::callbacks
{
    VEIL_ABI_FUNCTION_SIMPLIFIED(add_log)
}
