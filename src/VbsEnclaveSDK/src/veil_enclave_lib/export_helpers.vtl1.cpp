// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "pch.h"

#include "export_helpers.vtl1.h"

namespace veil::vtl1::implementation::export_helpers
{
    wil::srwlock g_enclaveErrorsMutex;
    std::unordered_map<DWORD, std::vector<enclave_error>> g_enclaveErrors;
}
