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
        auto logFilePath = data->logFilePath;
        std::filesystem::path filePath(logFilePath);
        std::wofstream wofs(filePath, std::ios::app);
        wofs << veil::any::telemetry::activity::CreateTimestamp() + L": ";
        wofs << data->log << std::endl;
        wofs.close();
    }
}

namespace veil::vtl0::implementation::callbacks
{
    VEIL_ABI_FUNCTION_SIMPLIFIED(add_log)
}
