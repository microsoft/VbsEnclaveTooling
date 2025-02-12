// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <Windows.h>
#include <sqlite3.h>

// How to add a new callback:
//
// * Add a callback function to the Vtl0VfsCallbacks struct.
// * Define a new payload structure or use an existing one.
// * If you define a new one, derive it from WinLastErrorContext
//   and add it to the union in Vtl0SharedMemoryBuffer.
// * Add a specialization to Vtl0AssociatedContext to associate
//   your callback with the payload structure.
// * In enclavevfs.cpp, add a "wineXxx" function that fills out a context
//   structure and calls the host by doing a
//
//   rc = CallVtl0VfsFunction<&Vtl0VfsCallbacks::winXxx>(context);
//
//   If CallVtl0VfsFunction returns failure, make sure to preserve the
//   last error code. This means either (1) not doing anything that
//   affects GetLastError(), or (2) using a wil::last_error_context
//   to preserve the last error code:
//
//   rc = CallVtl0VfsFunction<&Vtl0VfsCallbacks::winXxx>(context);
//   if (rc != SQLITE_OK)
//   {
//       wil::last_error_context preserveLastError;
//       extra_cleanup_stuff();
//   }
//   return rc;
//
//   If CallVtl0VfsFunction returns SQLITE_OK but the values returned from
//   VTL0 fail validation, then remember to call SetLastError() yourself.
//
//   rc = CallVtl0VfsFunction<&Vtl0VfsCallbacks::winXxx>(context);
//   if (rc == SQLITE_OK)
//   {
//       if (FAILED(extra_validation(context.value))
//       {
//           SetLastError(ERROR_INTERNAL_ERROR);
//           rc = SQLITE_INTERNAL;
//       }
//   }
// * In hostvfsshims.cpp, add a "winhXxxImpl" function of the form
//
//   int winhXxxImpl(_Inout_ PayloadStructure* args)
//   {
//       ... do work ...
//       return SQLITE_OK; // or error code
//   }
//
// * In hostvfsshims.cpp, add a "winhXxx" function of the form
//
//   PVOID winhXxx(_In_ PVOID context)
//   {
//       return winhDispatchCallback<&Vtl0VfsCallbacks::winXxx, winhXxxImpl>(context);
//   }
//
struct Vtl0VfsCallbacks
{
    // Function addresses to SQLite VFS functions in VTL0
    PENCLAVE_ROUTINE winOpen;                  // WinOpenContext
    PENCLAVE_ROUTINE winClose;                 // WinFileOpContext
    PENCLAVE_ROUTINE winRead;                  // WinRWContext
    PENCLAVE_ROUTINE winFileSize;              // WinFileSizeContext
    PENCLAVE_ROUTINE winLock;                  // WinLockContext
    PENCLAVE_ROUTINE winUnlock;                // WinLockContext
    PENCLAVE_ROUTINE winAccess;                // WinAccessContext
    PENCLAVE_ROUTINE winCurrentTimeInt64;      // WinCurrentTimeInt64Context
    PENCLAVE_ROUTINE winWrite;                 // WinRWContext
    PENCLAVE_ROUTINE winCheckReservedLock;     // WinCheckReservedLock
    PENCLAVE_ROUTINE winFileControl;           // WinFileControl
    PENCLAVE_ROUTINE winDelete;                // WinDeleteContext
    PENCLAVE_ROUTINE winTruncate;              // WinTruncateContext
    PENCLAVE_ROUTINE winSync;                  // WinSyncContext
    PENCLAVE_ROUTINE winDeviceCharacteristics; // WinDeviceCharacteristics
    PENCLAVE_ROUTINE winShmMap;                // WinShmMapContext
    PENCLAVE_ROUTINE winShmLock;               // WinShmLockContext
    PENCLAVE_ROUTINE winShmBarrier;            // WinFileOpContext
    PENCLAVE_ROUTINE winShmUnmap;              // WinShmUnmapContext
};

struct Vtl0SharedMemoryBuffer;

typedef struct VfsConfigParams VfsConfigParams;
struct VfsConfigParams
{
    Vtl0VfsCallbacks const* vtl0Callbacks;
    Vtl0SharedMemoryBuffer* sharedMemory; // Shared memory for parameter passing to the VTL.0 side (Array of ENCLAVE_MAX_THREADS buffers)
};

// This method needs to be exported by the enclave DLL that will link to this library
EXTERN_C PVOID WINAPI ConfigureEnclaveVfs(_In_ PVOID vfsConfigParams);

// Performs registration of the 'Win32e' VFS
//
int RegisterWin32eVfs();

/*
 * Types used to call into the VFS methods in the VTL0 side
 * Naming of members in most cases match those of the arguments of the VFS methods in SQLite
 * for ease of mapping.
 */
/*
** Maximum pathname length (in chars) for Win32.  This should normally be
** MAX_PATH.
*/
#ifndef SQLITE_WIN32_MAX_PATH_CHARS
#define SQLITE_WIN32_MAX_PATH_CHARS (MAX_PATH)
#endif

/*
** Maximum pathname length (in bytes) for the UTF-8 version of a Win32 path.
**
** Range             UTF-16 code units   UTF-8 code units    Factor
** U+0000 to U+007F        1                      1            1
** U+0080 to U+07FF        1                      2            2
** U+0800 to U+FFFF        1                      3            3
** U+010000 to U+10FFFF    2                      4            2
**
** Therefore the worst case expansion is a factor of 3.
*/
#ifndef SQLITE_WIN32_MAX_PATH_BYTES
#define SQLITE_WIN32_MAX_PATH_BYTES (SQLITE_WIN32_MAX_PATH_CHARS * 3)
#endif

// Private VTL0 structure, opaque to VTL1, which treats the pointer as just a handle.
struct Vtl0SqliteFile;

struct WinLastErrorContext
{
    DWORD lastError;                        /* OUT */
};

struct WinOpenContext : WinLastErrorContext
{
    int flags;                               /* Open mode flags */
    int outFlags;                            /* OUT: Status return flags */
    Vtl0SqliteFile* vtl0File;                /* OUT: Receives VTL0 file handle here (opaque to VTL1) */
    void* rwBuffer;                          /* OUT: The buffer in VTL0 used for read and write */
    int rwBufferSize;                        /* OUT: The size of the buffer (max 2GB-1 bytes) */
    char zName[SQLITE_WIN32_MAX_PATH_BYTES]; /* Name of the file (UTF-8) */
};

struct WinFileOpContext : WinLastErrorContext
{
    Vtl0SqliteFile* vtl0File; /* File to operate on */
};

struct WinRWContext : WinLastErrorContext
{
    Vtl0SqliteFile* vtl0File; /* File to read from/write to */
    int amt;                  /* Number of bytes to read/write */
    sqlite3_int64 offset;     /* Begin reading/writing at this offset */
};

struct WinFileSizeContext : WinLastErrorContext
{
    Vtl0SqliteFile* vtl0File; /* File to check the size from */
    sqlite3_int64 size;       /* the output file size */
};

struct WinLockContext : WinLastErrorContext
{
    Vtl0SqliteFile* vtl0File; /* File to lock */
    int locktype;
};

struct WinAccessContext : WinLastErrorContext
{
    int flags;                               /* Type of test to make on this file */
    int resOut;                              /* OUT: Result */
    char zName[SQLITE_WIN32_MAX_PATH_BYTES]; /* Name of the file (UTF-8) */
};

struct WinCurrentTimeInt64Context : WinLastErrorContext
{
    sqlite3_int64 now;                      /* OUT: Result */
};

struct WinCheckReservedLock : WinLastErrorContext
{
    Vtl0SqliteFile* vtl0File;
    int result; /* OUT */
};

struct WinFileControl : WinLastErrorContext
{
    Vtl0SqliteFile* vtl0File;
    int op;

    // Declaring FileControl payload types in a union solves two problems.
    // (1) Ensures proper alignment.
    // (2) Ensures that the buffer is big enough to hold the largest type.
    union WinFileControlTypes
    {
        int intVal;
        sqlite3_int64 sqlite3_int64Val;
    } data; /* INOUT */
};

struct WinDeleteContext : WinLastErrorContext
{
    char zName[SQLITE_WIN32_MAX_PATH_BYTES]; /* Name of the file (UTF-8) */
};

struct WinTruncateContext : WinLastErrorContext
{
    Vtl0SqliteFile* vtl0File; /* File to truncate */
    sqlite3_int64 size;       /* Size to truncate file to */
};

struct WinSyncContext : WinLastErrorContext
{
    Vtl0SqliteFile* vtl0File; /* File to sync */
    int flags;
};

struct WinDeviceCharacteristics : WinLastErrorContext
{
    Vtl0SqliteFile* vtl0File;
    int result; /* OUT: characteristics */
};

struct WinShmMapContext : WinLastErrorContext
{
    Vtl0SqliteFile* vtl0File; /* Handle open on database file */
    int iRegion;              /* Region to retrieve */
    int szRegion;             /* Size of each region */
    int isWrite;              /* True: Create or find existing mapping, extend file if necessary; False: Find existing mapping */
    volatile void* p;         /* OUT: Mapped memory (pointer to szRegion bytes) */
};

struct WinShmLockContext : WinLastErrorContext
{
    Vtl0SqliteFile* vtl0File; /* Database holding the shared memory */
    int ofst;                 /* First lock to obtain */
    int n;                    /* Number of locks to obtain */
    int flags;                /* Type of lock to get */
};

struct WinShmUnmapContext : WinLastErrorContext
{
    Vtl0SqliteFile* vtl0File; /* Database holding the shared memory */
    int deleteFlag;           /* Delete shared-memory if true */
};

struct Vtl0SharedMemoryBuffer
{
    // All of the context structures go in here, so that the compiler
    // can choose the largest one to establish the size of the shared buffer,
    // and choose the most alignment-constrained one to establish the
    // alignment of the shared buffer.
    union
    {
        WinOpenContext winOpenContext;
        WinFileOpContext winFileOpContext;
        WinRWContext winRWContect;
        WinFileSizeContext winLockContext;
        WinAccessContext winAccessContext;
        WinCurrentTimeInt64Context winCurrentTimeInt64Context;
        WinCheckReservedLock winCheckReservedLock;
        WinFileControl winFileControl;
        WinDeleteContext winDeleteContext;
        WinTruncateContext winTruncateContext;
        WinSyncContext winSyncContext;
        WinDeviceCharacteristics winDeviceCharacteristics;
        WinShmMapContext winShmMapContext;
        WinShmLockContext winShmLockContext;
        WinShmUnmapContext winShmUnmapContext;
    } data;
};

// Type checking helpers to make sure the enclave and host agree on the
// payload structures.

template<auto mem> struct Vtl0AssociatedContext;
template <> struct Vtl0AssociatedContext<&Vtl0VfsCallbacks::winOpen> { using type = WinOpenContext; };
template <> struct Vtl0AssociatedContext<&Vtl0VfsCallbacks::winClose> { using type = WinFileOpContext; };
template <> struct Vtl0AssociatedContext<&Vtl0VfsCallbacks::winRead> { using type = WinRWContext; };
template <> struct Vtl0AssociatedContext<&Vtl0VfsCallbacks::winFileSize> { using type = WinFileSizeContext; };
template <> struct Vtl0AssociatedContext<&Vtl0VfsCallbacks::winLock> { using type = WinLockContext; };
template <> struct Vtl0AssociatedContext<&Vtl0VfsCallbacks::winUnlock> { using type = WinLockContext; };
template <> struct Vtl0AssociatedContext<&Vtl0VfsCallbacks::winAccess> { using type = WinAccessContext; };
template <> struct Vtl0AssociatedContext<&Vtl0VfsCallbacks::winCurrentTimeInt64> { using type = WinCurrentTimeInt64Context; };
template <> struct Vtl0AssociatedContext<&Vtl0VfsCallbacks::winWrite> { using type = WinRWContext; };
template <> struct Vtl0AssociatedContext<&Vtl0VfsCallbacks::winCheckReservedLock> { using type = WinCheckReservedLock; };
template <> struct Vtl0AssociatedContext<&Vtl0VfsCallbacks::winFileControl> { using type = WinFileControl; };
template <> struct Vtl0AssociatedContext<&Vtl0VfsCallbacks::winDelete> { using type = WinDeleteContext; };
template <> struct Vtl0AssociatedContext<&Vtl0VfsCallbacks::winTruncate> { using type = WinTruncateContext; };
template <> struct Vtl0AssociatedContext<&Vtl0VfsCallbacks::winSync> { using type = WinSyncContext; };
template <> struct Vtl0AssociatedContext<&Vtl0VfsCallbacks::winDeviceCharacteristics> { using type = WinDeviceCharacteristics; };
template <> struct Vtl0AssociatedContext<&Vtl0VfsCallbacks::winShmMap> { using type = WinShmMapContext; };
template <> struct Vtl0AssociatedContext<&Vtl0VfsCallbacks::winShmLock> { using type = WinShmLockContext; };
template <> struct Vtl0AssociatedContext<&Vtl0VfsCallbacks::winShmBarrier> { using type = WinFileOpContext; };
template <> struct Vtl0AssociatedContext<&Vtl0VfsCallbacks::winShmUnmap> { using type = WinShmUnmapContext; };

#ifndef RETURN_HR_AS_PVOID
#define RETURN_HR_AS_PVOID(hr) return (PVOID)((ULONG_PTR)(hr) & 0x00000000FFFFFFFF);
#endif
