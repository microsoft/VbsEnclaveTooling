// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "pch.h"

#include <format>

#include <gsl/gsl_util>

#include <sddl.h>

#include "logger.vtl0.h"
#include "utils.any.h"

#include "hello.vtl0.h"

namespace veil::vtl0::logger
{
    std::mutex logMutex;
}

namespace simplified
{
    static void add_log(veil::any::implementation::args::add_log* data)
    {
        veil::vtl0::logger::logger::AddTimestampedLog(data->log, data->logFilePath);
    }
}

namespace veil::vtl0::implementation::callbacks
{
    VEIL_ABI_FUNCTION_SIMPLIFIED(add_log)
}
