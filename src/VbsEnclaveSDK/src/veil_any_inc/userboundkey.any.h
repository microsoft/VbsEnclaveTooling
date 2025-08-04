// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#ifdef VEIL_IMPLEMENTATION

namespace veil::any::implementation::userboundkey
{
    uintptr_t to_abi(const void* ptr)
    {
        return reinterpret_cast<uintptr_t>(ptr);
    }

    void* from_abi(uintptr_t ptr)
    {
        return reinterpret_cast<void*>(ptr);
    }
}

#endif
