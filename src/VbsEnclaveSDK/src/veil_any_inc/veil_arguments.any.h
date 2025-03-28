// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <span>

#include <veil.any.h>
#include <hello.any.h>

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
            // hello-secured encryption key
            //
            struct hellokeys_create_or_open_hello_key
            {
                wchar_t helloKeyName[256];
                wchar_t pinMessage[256];
                bool openOnly;

                // out
                NCRYPT_KEY_HANDLE helloKeyHandle;
                bool createdKey;
            };
            
            struct hellokeys_get_challenge
            {
                NCRYPT_KEY_HANDLE helloKeyHandle;

                // out
                std::vector<uint8_t>* challenge; // TODO:SECURITY-TOOLING fix complex type
            };

            struct hellokeys_send_attestation_report
            {
                NCRYPT_KEY_HANDLE helloKeyHandle;
                veil::any::args::data_blob report;
            };

            struct hellokeys_finalize_key
            {
                NCRYPT_KEY_HANDLE helloKeyHandle;
                NCRYPT_NGC_CACHE_CONFIG cacheConfig;
                bool promptForUnlock;

                // out
            };

            struct hellokeys_send_ngc_request
            {
                NCRYPT_KEY_HANDLE helloKeyHandle;
                bool promptForUnlock;
                veil::any::args::data_blob requests[3];

                // out
                veil::any::args::data_blob responses[3];
            };

            struct add_log
            {
                wchar_t log[256];

                // out
            };
        }
    }
}


