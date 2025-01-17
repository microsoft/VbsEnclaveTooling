#include "pch.h"

#include <wil/resource.h>
#include <wil/token_helpers.h>

#include "veil.any.h"
#include "veil_arguments.any.h"

#include "enclave_api.vtl0.h"
#include "exports.vtl0.h"

namespace veil::vtl0::exports
{
    HRESULT register_callbacks(void* enclave, veil::implementation::callback_t* callbackAddresses)
    {
        veil::any::implementation::args::register_callbacks data = {};
        data.callbackAddresses = callbackAddresses;

        THROW_IF_FAILED(veil::vtl0::enclave::implementation::call_enclave_function(enclave, veil::implementation::export_ordinals::register_callbacks, data));

        return S_OK;
    }

    HRESULT retrieve_enclave_error_for_thread(void* enclave, std::vector<uint8_t>& proof, std::vector<uint8_t>& userId)
    {
        veil::any::implementation::args::retrieve_enclave_error_for_thread data = {};

        THROW_IF_FAILED(veil::vtl0::enclave::implementation::call_enclave_function(enclave, veil::implementation::export_ordinals::retrieve_enclave_error_for_thread, data));

        return S_OK;
    }
}
