// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#ifdef VEIL_IMPLEMENTATION

namespace veil::any::implementation::taskpool
{
    uintptr_t to_abi(const void* enclave)
    {
        auto ptr = uintptr_t {};
        ptr = reinterpret_cast<uint64_t>(enclave);
        return ptr;
    }

    void* from_abi(uintptr_t ptr)
    {
        return reinterpret_cast<void*>(ptr);
    }
}

#endif
