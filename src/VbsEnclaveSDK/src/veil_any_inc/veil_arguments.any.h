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
                uint32_t status;
            };

            struct register_callbacks
            {
                veil::implementation::callback_t* callbackAddresses;
            };

            struct thread_make
            {
                void* enclave;
                uint64_t threadInstanceVtl1;
                void* threadInstanceVtl0;
            };

            struct thread_run
            {
                uint64_t threadId;
            };

            struct threadpool_make
            {
                void* enclave;
                uint64_t threadpoolInstanceVtl1;
                void* threadpoolInstanceVtl0;
                uint32_t threadCount;
                bool mustFinishAllQueuedTasks = true;
                void* context;
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
                uint64_t threadpoolInstance;
                uint64_t taskHandle;
            };
        }
    }
}


