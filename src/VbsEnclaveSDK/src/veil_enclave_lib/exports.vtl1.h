// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "veil_arguments.any.h"

namespace veil::vtl1::implementation::exports
{
    HRESULT register_callbacks(_Inout_ veil::any::implementation::args::register_callbacks* params) noexcept;
    HRESULT retrieve_enclave_error_for_thread(_Inout_ veil::any::implementation::args::retrieve_enclave_error_for_thread* params) noexcept;
}
