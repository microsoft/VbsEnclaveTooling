// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

// Structures private to VTL0

/* Size of header before each frame in wal */
#define WAL_FRAME_HDRSIZE 24

#ifndef SQLITE_DEFAULT_PAGE_SIZE
#define SQLITE_DEFAULT_PAGE_SIZE 4096
#endif

constexpr size_t SQLITE_RW_BUFFER_SIZE = SQLITE_DEFAULT_PAGE_SIZE + WAL_FRAME_HDRSIZE;

struct Vtl0SqliteFile
{
    char zName[sizeof(std::declval<WinOpenContext>().zName)];
    BYTE rwBuffer[SQLITE_RW_BUFFER_SIZE];

    // Appended to the Vtl0SqliteFile is the sqlite3_file for win32Vfs.
    sqlite3_file* VfsFile()
    {
        return reinterpret_cast<sqlite3_file*>(this + 1);
    }

    ~Vtl0SqliteFile()
    {
        auto vfsFile = VfsFile();
        if (vfsFile->pMethods)
        {
            vfsFile->pMethods->xClose(vfsFile);
        }
    }
};
