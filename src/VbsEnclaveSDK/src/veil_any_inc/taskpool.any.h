// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#ifdef VEIL_IMPLEMENTATION

namespace veil::any::implementation::taskpool
{
    DeveloperTypes::ULongPtr to_abi(const void* enclave)
    {
        auto ptr = DeveloperTypes::ULongPtr {};
        ptr.value = reinterpret_cast<uint64_t>(enclave);
        return ptr;
    }

    void* from_abi(const DeveloperTypes::ULongPtr& ptr)
    {
        return reinterpret_cast<void*>(ptr.value);
    }
}

#endif
