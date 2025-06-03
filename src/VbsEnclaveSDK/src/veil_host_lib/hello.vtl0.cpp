// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "pch.h"

#define VEIL_IMPLEMENTATION

#include <VbsEnclave\HostApp\Stubs.h>

#include "hello.vtl0.h"

namespace veil::vtl0::implementation::callins
{
    void enclave_load_user_bound_key(_In_ void* enclave, _In_ std::wstring keyName, _In_ std::wstring flags, _In_ std::wstring cache)
    {
        // Initialize enclave interface
        auto enclaveInterface = veil_abi::VTL0_Stubs::export_interface(enclave);
        THROW_IF_FAILED(enclaveInterface.RegisterVtl0Callbacks());

        THROW_IF_FAILED(enclaveInterface.enclave_load_user_bound_key(keyName, flags, cache));
    }
}
