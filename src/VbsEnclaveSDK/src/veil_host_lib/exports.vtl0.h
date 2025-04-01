// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "..\veil_any_inc\veil.any.h"

namespace veil::vtl0::exports
{
    HRESULT register_callbacks(void* enclave, veil::implementation::callback_t* callbackAddresses);
    HRESULT retrieve_enclave_error_for_thread(void* enclave, std::vector<uint8_t>& proof, std::vector<uint8_t>& userId);
}
