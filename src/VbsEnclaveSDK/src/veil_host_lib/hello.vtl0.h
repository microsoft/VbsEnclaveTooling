// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "..\veil_any_inc\veil.any.h"
#include "..\veil_any_inc\veil_arguments.any.h"

#include "enclave_api.vtl0.h"
#include "exports.vtl0.h"

namespace veil::vtl0::implementation::callbacks
{
    void* hellokeys_create_or_open_hello_key(void* args) noexcept;
    void* hellokeys_close_handle_vtl1_ncrypt_key(void* args) noexcept;
    void* hellokeys_get_challenge(void* args) noexcept;
    void* hellokeys_send_attestation_report(void* args) noexcept;
    void* hellokeys_finalize_key(void* args) noexcept;

    void* hellokeys_send_ngc_request(void* args) noexcept;
}
