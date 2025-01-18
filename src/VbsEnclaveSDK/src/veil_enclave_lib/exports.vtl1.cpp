// © Microsoft Corporation. All rights reserved.

#include "pch.h"

#include <wil/stl.h>

#include "veil_arguments.any.h"

#include "exports.vtl1.h"
#include "registered_callbacks.vtl1.h"


namespace veil::vtl1::implementation::exports
{
    HRESULT retrieve_enclave_error_for_thread(_Inout_ veil::any::implementation::args::retrieve_enclave_error_for_thread* params) noexcept try
    {
        (void)params;

        return S_OK;
    }
    CATCH_RETURN()

    HRESULT register_callbacks(_Inout_ veil::any::implementation::args::register_callbacks* params) noexcept try
    {
        veil::vtl1::implementation::register_callbacks(params->callbackAddresses);
        return S_OK;
    }
    CATCH_RETURN()
}
