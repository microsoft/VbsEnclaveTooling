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
            struct retrieve_enclave_error_for_thread
            {
                DWORD threadId;

                // out
                veil::enclave_error error;
            };

            struct register_callbacks
            {
                veil::implementation::callback_t* callbackAddresses;
            };

            struct threadpool_make
            {
                void* enclave;
                uint64_t threadpoolInstanceVtl1;
                uint32_t threadCount;
                bool mustFinishAllQueuedTasks = true;

                // out
                void* threadpoolInstanceVtl0;
            };

            struct threadpool_delete
            {
                void* threadpoolInstanceVtl0;
            };

            struct threadpool_schedule_task
            {
                void* threadpoolInstanceVtl0;
                uint64_t taskHandle;
            };

            struct threadpool_run_task
            {
                uint64_t threadpoolInstanceVtl1;
                uint64_t taskHandle;
            };
        }
    }
}


