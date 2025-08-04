// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "pch.h"

#include <wil/resource.h>
#include <wil/token_helpers.h>

#include "enclave_api.vtl0.h"

#include <VbsEnclave\HostApp\Stubs\Trusted.h>

namespace veil::vtl0::enclave_api
{
    void register_callbacks(void* enclave)
    {
        // Initialize enclave interface
        auto enclaveInterface = veil_abi::Trusted::Stubs::export_interface(enclave);
        THROW_IF_FAILED(enclaveInterface.RegisterVtl0Callbacks());
    }
}
