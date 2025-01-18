// © Microsoft Corporation. All rights reserved.

#include "pch.h"

#include <functional>
#include <map>
#include <vector>

#include <safeint.h>

#include <wil/stl.h>

#include "veil_arguments.any.h"

#include "enclave_interface.vtl1.h"
#include "exports.vtl1.h"
#include "mutualauth.vtl1.h"
#include "registered_callbacks.vtl1.h"
#include "threadpool.vtl1.h"
#include "utils.vtl1.h"


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
        veil::vtl1::implementation::register_callback(params->callbackAddresses);
        return S_OK;
    }
    CATCH_RETURN()
}
