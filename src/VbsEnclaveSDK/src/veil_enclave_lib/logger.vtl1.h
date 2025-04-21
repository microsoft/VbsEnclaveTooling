#pragma once

#include <span>

#include <gsl/gsl_util>
#include <wil/stl.h>

#include "..\veil_any_inc\logger.any.h"

namespace veil::vtl1::logger
{
    namespace implementation
    {
        namespace callouts
        {
            void add_log(std::wstring_view log, std::wstring_view logFilePath);
        }

        inline void add_log_from_enclave(
            std::wstring_view log,
            veil::any::logger::eventLevel logLevel,
            veil::any::logger::eventLevel runtimeLogLevel,
            std::wstring_view logFilePath)
        {

            if ((int)logLevel <= (int)runtimeLogLevel)
            {
                implementation::callouts::add_log(log, logFilePath);
            }
        }
    }
}
