// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "pch.h"

#include "enclavethreading.h"

ULONG g_TlsSlot;    // TLS slot number that stores the thread's index

LONG GetCurrentEnclaveThreadIndex()
{
    // Retrieve the thread number from the Tls slot
    auto val = reinterpret_cast<ULONG_PTR>(TlsGetValue(g_TlsSlot));
    // Since our value is 1 based, 0 means no value set in the slot
    // so we return -1 as the index
    return ((LONG)val -1);
}
