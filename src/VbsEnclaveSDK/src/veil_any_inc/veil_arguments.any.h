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
                UINT32 status;
            };

            struct threadpool_make
            {
                void* enclave;
                uint64_t threadpoolInstance_vtl1;
                uint32_t threadCount;
                bool mustFinishAllQueuedTasks = true;
                void* context;
                void* threadpoolInstance_vtl0;
            };

            struct threadpool_task_handle
            {
                void* threadpool_instance;
                UINT64 task_handle;
            };

            struct threadpool_run_task
            {
                UINT64 threadpoolInstance;
                UINT64 taskHandle;
            };
        }
    }
}


