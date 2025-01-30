// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <veil.any.h>

#ifndef ENCLAVE_REPORT_DATA_LENGTH
#define ENCLAVE_REPORT_DATA_LENGTH 64
#endif


namespace veil::any
{
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
        }
    }
}


