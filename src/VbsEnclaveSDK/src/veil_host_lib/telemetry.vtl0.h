// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "veil.any.h"
#include "veil_arguments.any.h"

#include "enclave_api.vtl0.h"
#include "exports.vtl0.h"

namespace veil::vtl0::implementation::callbacks
{
    void* add_log(void* args) noexcept;
}
#pragma once
