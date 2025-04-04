// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "pch.h"

#include <wil/stl.h>

#include "..\veil_any_inc\veil.any.h"

#include "exports.vtl1.h"
#include "export_helpers.vtl1.h"
#include "registered_callbacks.vtl1.h"


namespace veil::vtl1::implementation::exports
{
    HRESULT register_callbacks(_Inout_ veil::any::implementation::args::register_callbacks* params) noexcept try
    {
        veil::vtl1::implementation::register_callbacks(params->callbackAddresses);
        return S_OK;
    }
    CATCH_RETURN()
    
    HRESULT retrieve_enclave_error_for_thread(_Inout_ veil::any::implementation::args::retrieve_enclave_error_for_thread* params) noexcept try
    {
        auto threadId = params->threadId;
        if (auto error = veil::vtl1::implementation::export_helpers::pop_back_thread_enclave_error(threadId))
        {
            veil::vtl1::implementation::export_helpers::copy_enclave_error(params->error, error.value());
        }
        return S_OK;
    }
    CATCH_RETURN()
}
