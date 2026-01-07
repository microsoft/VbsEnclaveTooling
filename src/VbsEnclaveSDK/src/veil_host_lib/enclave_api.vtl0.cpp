// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "pch.h"
#include "enclave_api.vtl0.h"
#include <VbsEnclave\HostApp\Stubs\Trusted.h>

VEIL_ABI_API HRESULT register_veil_callbacks(_In_ void* enclave)
{
    try
    {
        // Initialize enclave interface
        auto enclaveInterface = veil_abi::Trusted::Stubs::export_interface(enclave);
        THROW_IF_FAILED(enclaveInterface.RegisterVtl0Callbacks());
        return S_OK;
    }
    CATCH_RETURN();
}
