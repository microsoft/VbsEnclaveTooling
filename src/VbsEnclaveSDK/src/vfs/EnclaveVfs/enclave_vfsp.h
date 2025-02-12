// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

/*
** The sqlite3_file object for the enclave VFS
*/

struct Vtl1SqliteFile : sqlite3_file
{
    Vtl0SqliteFile* vtl0File;   /* The real underlying file in the VTL.0 side */
    void* rwBuffer;             /* The buffer in VTL0 used for read and write */
    int rwBufferSize;           /* The size of the buffer (maximum 2GB-1) */
};
inline Vtl1SqliteFile* Vtl1FileFromSqliteFile(sqlite3_file* id)
{
    return static_cast<Vtl1SqliteFile*>(id);
}

extern void* sqlite3MallocZero(sqlite_uint64 n);

void EnclaveSleep(DWORD milliseconds);

// This API should be used to get the Mutex methods on the enclave side,
// and provide it using the SQLITE_CONFIG_MUTEX option of the sqlite3_config()
// (before calling sqlite3_initialize()).
sqlite3_mutex_methods const* GetEnclaveMutexMethods(void);
