// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "pch.h"

#include "enclave_vfs.h"

#include <sqlite3.h>

SQLITE_API int sqlite3_os_init()
{
    return RegisterWin32eVfs();
}

SQLITE_API int sqlite3_os_end()
{
    return SQLITE_OK;
}
