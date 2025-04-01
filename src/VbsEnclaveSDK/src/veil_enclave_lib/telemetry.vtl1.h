#pragma once

#include <span>

#include <gsl/gsl_util>
#include <wil/stl.h>

#include "veil_arguments.any.h"
#include "telemetry.any.h"
#include "utils.any.h"

#include "future.vtl1.h"
#include "memory.vtl1.h"
#include "object_table.vtl1.h"
#include "registered_callbacks.vtl1.h"
#include "utils.vtl1.h"
#include "vtl0_functions.vtl1.h"

namespace veil::vtl1::telemetry
{
    namespace implementation
    {
        namespace callouts
        {
            void add_log(std::wstring_view log, std::wstring_view logFilePath)
            {
                // Call out to VTL0 (TODO:NOT SAFE UNTIL TOOLING WORK COMPLETE)
                auto data = veil::vtl1::memory::allocate_vtl0<veil::any::implementation::args::add_log>();
                
                {
                    auto cnt = veil::any::math_max(sizeof(data->log), log.size());
                    wcscpy_s(data->log, cnt, log.data());
                    data->log[cnt] = L'\0';
                }
                {
                    auto cnt = veil::any::math_max(sizeof(data->logFilePath), logFilePath.size());
                    wcscpy_s(data->logFilePath, cnt, logFilePath.data());
                    data->logFilePath[cnt] = L'\0';
                }

                void* output {};
                auto func = veil::vtl1::implementation::get_callback(veil::implementation::callback_id::add_log);

                THROW_IF_WIN32_BOOL_FALSE(::CallEnclave(func, reinterpret_cast<void*>(data.get()), TRUE, reinterpret_cast<void**>(&output)));
                THROW_IF_FAILED(pvoid_to_hr(output));
            }
        }

        inline void add_log_from_enclave(
            std::wstring_view log,
            veil::any::telemetry::eventLevel logLevel,
            veil::any::telemetry::eventLevel runtimeLogLevel,
            std::wstring_view logFilePath)
        {

            if ((int)logLevel <= (int)runtimeLogLevel)
            {
                implementation::callouts::add_log(log, logFilePath);
            }
        }
    }
}
