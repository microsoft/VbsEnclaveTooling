// <copyright placeholder>

#pragma once

#include "pch.h"

#include <wil/resource.h>
#include <wil/token_helpers.h>

#include "callbacks.vtl0.h"
#include "enclave_api.vtl0.h"
#include "exports.vtl0.h"

namespace veil::vtl0::enclave_api
{
    void unlock_for_app_user(void* enclave)
    {
        // todo
    }

    void register_callbacks(void* enclave)
    {
        THROW_IF_FAILED(veil::vtl0::exports::register_callbacks(enclave, veil::vtl0::implementation::callbacks::callback_addresses));
    }
}
