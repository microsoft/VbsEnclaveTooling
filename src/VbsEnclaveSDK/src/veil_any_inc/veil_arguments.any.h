// <copyright placeholder>

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
        }
    }
}


