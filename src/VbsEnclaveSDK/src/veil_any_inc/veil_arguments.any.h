// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <span>

#include "veil.any.h"

#ifndef ENCLAVE_REPORT_DATA_LENGTH
#define ENCLAVE_REPORT_DATA_LENGTH 64
#endif

// TODO:SECURITY-TOOLING remove
#include <string>
#include <vector>
#include <ncrypt.h>

namespace veil::any
{
    namespace args
    {
        struct data_blob
        {
            uint8_t* data;
            size_t size;

            // Implicit conversion operator to std::span
            operator std::span<uint8_t const>() const
            {
                return {data, size};
            }
        };
    }

    namespace implementation
    {
        namespace args
        {
            struct register_callbacks
            {
                veil::implementation::callback_t* callbackAddresses;
            };

            struct retrieve_enclave_error_for_thread
            {
                DWORD threadId;

                // out
                veil::enclave_error error;
            };

            //
            // taskpool
            //
            struct taskpool_make
            {
                void* enclave;
                uint64_t taskpoolInstanceVtl1;
                uint32_t threadCount;
                bool mustFinishAllQueuedTasks;

                // out
                void* taskpoolInstanceVtl0;
            };

            struct taskpool_delete
            {
                void* taskpoolInstanceVtl0;
            };

            struct taskpool_schedule_task
            {
                void* taskpoolInstanceVtl0;
                uint64_t taskId;
            };

            struct taskpool_run_task
            {
                uint64_t taskpoolInstanceVtl1;
                uint64_t taskId;
            };

            struct taskpool_cancel_queued_tasks
            {
                void* taskpoolInstanceVtl0;
            };

            //
            // logger
            //
            struct add_log
            {
                wchar_t log[2048];
                wchar_t logFilePath[256];

                // out
            };
        }
    }
}


