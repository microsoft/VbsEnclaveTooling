// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "pch.h"
#include <sqlite3.h>
#include <bcrypt.h>

#include "enclave_vfs.h"
#include "enclave_vfsp.h"
#include "data_enclave.h" // HRESULT/SQLITE interop helpers
#include "utils.h"
#include "vtl0util.h"

wil::srwlock g_vtl0VfsCallbackInitLock;
Vtl0VfsCallbacks g_vtl0VfsCallbacks;
std::atomic<Vtl0SharedMemoryBuffer*> g_vtl0SharedMemory = nullptr;

#pragma region IO_METHODS

int wineClose(sqlite3_file* id)
{
    Vtl1SqliteFile* pVtl1File = Vtl1FileFromSqliteFile(id);

    // Null out the vtable so sqlite can't close us again.
    pVtl1File->pMethods = nullptr;

    WinFileOpContext context = { 0 };
    context.vtl0File = std::exchange(pVtl1File->vtl0File, nullptr);
    return CallVtl0VfsFunction<&Vtl0VfsCallbacks::winClose>(context);
}

static int wineRead(
    sqlite3_file* id,   /* File to read from */
    void* pBuf,         /* Write content into this buffer */
    int amt,             /* Number of bytes to read */
    sqlite3_int64 offset /* Begin reading at this offset */
)
{
    Vtl1SqliteFile* pVtl1File = Vtl1FileFromSqliteFile(id);

    int rc = SQLITE_OK;
    // Break up the read into chunks of at most rwBufferSize bytes.
    while (amt > 0)
    {
        int chunkSize = (std::min)(amt, pVtl1File->rwBufferSize);

        {
            // Scope the context so we aren't tempted to use it after VTL0
            // may have maliciously modified the structure.
            WinRWContext context = {0};
            context.vtl0File = pVtl1File->vtl0File;
            context.amt = chunkSize;
            context.offset = offset;
            rc = CallVtl0VfsFunction<&Vtl0VfsCallbacks::winRead>(context);
        }

        // Consume the results before checking for error, because
        // SQLITE_IOERR_SHORT_READ returns a partial buffer that we want
        // to copy back. Note that rwBuffer has already been validated as VTL0 memory.
        memcpy_s(pBuf, amt, pVtl1File->rwBuffer, chunkSize);

        // Advance to next chunk
        amt -= chunkSize;
        offset += chunkSize;
        pBuf = static_cast<BYTE*>(pBuf) + chunkSize;

        if (rc != SQLITE_OK)
        {
            break;
        }
    }

    // SQLITE_IOERRO_SHORT_READ requires us to zero-fill any unused memory.
    // No harm doing it unconditionally.
    ZeroMemory(pBuf, amt);

    return rc;
}

static int wineWrite(
    sqlite3_file* id,   /* File to write into */
    void const* pBuf,   /* The bytes to be written */
    int amt,             /* Number of bytes to write */
    sqlite3_int64 offset /* Offset into the file to begin writing at */
)
{
    Vtl1SqliteFile* pVtl1File = Vtl1FileFromSqliteFile(id);

    int rc = SQLITE_OK;
    // Break up the read into chunks of at most rwBufferSize bytes.
    while (amt > 0)
    {
        int chunkSize = (std::min)(amt, pVtl1File->rwBufferSize);
        // rwBuffer has already been validated as VTL0 memory.
        memcpy_s(pVtl1File->rwBuffer, pVtl1File->rwBufferSize, pBuf, chunkSize);

        {
            // Scope the context so we aren't tempted to use it after VTL0
            // may have maliciously modified the structure.
            WinRWContext context = {0};
            context.vtl0File = pVtl1File->vtl0File;
            context.amt = chunkSize;
            context.offset = offset;
            rc = CallVtl0VfsFunction<&Vtl0VfsCallbacks::winWrite>(context);
        }

        // Advance to next chunk
        amt -= chunkSize;
        offset += chunkSize;
        pBuf = static_cast<const BYTE*>(pBuf) + chunkSize;

        if (rc != SQLITE_OK)
        {
            break;
        }
    }

    return rc;
}

static int wineTruncate(sqlite3_file* id, sqlite3_int64 nByte)
{
    Vtl1SqliteFile* pVtl1File = Vtl1FileFromSqliteFile(id);

    WinTruncateContext context = { 0 };
    context.vtl0File = pVtl1File->vtl0File;
    context.size = nByte;

    int rc = CallVtl0VfsFunction<&Vtl0VfsCallbacks::winTruncate>(context);

    return rc;
}

static int wineSync(sqlite3_file* id, int flags)
{
    Vtl1SqliteFile* pVtl1File = Vtl1FileFromSqliteFile(id);

    WinSyncContext context = { 0 };
    context.vtl0File = pVtl1File->vtl0File;
    context.flags = flags;

    int rc = CallVtl0VfsFunction<&Vtl0VfsCallbacks::winSync>(context);

    return rc;
}

static int wineFileSize(sqlite3_file* id, sqlite3_int64* pSize)
{
    Vtl1SqliteFile* pVtl1File = Vtl1FileFromSqliteFile(id);

    WinFileSizeContext context = { 0 };
    context.vtl0File = pVtl1File->vtl0File;
    context.size = 0;

    int rc = CallVtl0VfsFunction<&Vtl0VfsCallbacks::winFileSize>(context);
    *pSize = context.size;

    return rc;
}

static int wineLock(sqlite3_file* id, int locktype)
{
    Vtl1SqliteFile* pVtl1File = Vtl1FileFromSqliteFile(id);

    WinLockContext context = { 0 };
    context.vtl0File = pVtl1File->vtl0File;
    context.locktype = locktype;

    int rc = CallVtl0VfsFunction<&Vtl0VfsCallbacks::winLock>(context);

    return rc;
}

static int wineUnlock(sqlite3_file* id, int locktype)
{
    Vtl1SqliteFile* pVtl1File = Vtl1FileFromSqliteFile(id);
    
    WinLockContext context = { 0 };
    context.vtl0File = pVtl1File->vtl0File;
    context.locktype = locktype;

    int rc = CallVtl0VfsFunction<&Vtl0VfsCallbacks::winUnlock>(context);

    return rc;
}

static int wineCheckReservedLock(sqlite3_file* id, int* pResOut)
{
    Vtl1SqliteFile* pVtl1File = Vtl1FileFromSqliteFile(id);

    WinCheckReservedLock context = { 0 };
    context.vtl0File = pVtl1File->vtl0File;

    int rc = CallVtl0VfsFunction<&Vtl0VfsCallbacks::winCheckReservedLock>(context);

    *pResOut = context.result;
    
    return rc;
}

static int wineFileControl(sqlite3_file* id, int op, void* pArg)
{
    Vtl1SqliteFile* pVtl1File = Vtl1FileFromSqliteFile(id);

    WinFileControl context = {0};
    context.vtl0File = pVtl1File->vtl0File;
    context.op = op;

    size_t argSize = 0;
    
    // These are the operations we support. If you need
    // another one, add a "case" for it. If the type you need
    // is missing, add it to WinFileControl::WinFileControlTypes.
    switch (op)
    {
    case SQLITE_FCNTL_LOCKSTATE:
        argSize = sizeof(context.data.intVal); // int
        break;

    case SQLITE_FCNTL_LAST_ERRNO:
        argSize = sizeof(context.data.intVal); // int
        break;

    case SQLITE_FCNTL_CHUNK_SIZE:
        argSize = sizeof(context.data.intVal); // int
        break;

    case SQLITE_FCNTL_SIZE_HINT:
        argSize = sizeof(context.data.sqlite3_int64Val); // sqlite3_int64
        break;

    case SQLITE_FCNTL_PERSIST_WAL:
        argSize = sizeof(context.data.intVal); // int
        break;

    case SQLITE_FCNTL_POWERSAFE_OVERWRITE:
        argSize = sizeof(context.data.intVal); // int
        break;

    default:
        return SQLITE_NOTFOUND;
    }

    memcpy_s(&context.data, sizeof(context.data), pArg, argSize);

    int rc = CallVtl0VfsFunction<&Vtl0VfsCallbacks::winFileControl>(context);

    memcpy_s(pArg, argSize, &context.data, argSize);

    return rc;
}

static int wineDeviceCharacteristics(sqlite3_file* id)
{
    Vtl1SqliteFile* pVtl1File = Vtl1FileFromSqliteFile(id);

    WinDeviceCharacteristics context = {0};
    context.vtl0File = pVtl1File->vtl0File;
    int rc = CallVtl0VfsFunction<&Vtl0VfsCallbacks::winDeviceCharacteristics>(context);
    return (rc == SQLITE_OK) ? context.result : 0;
}

static int wineShmMap(
    sqlite3_file* fd,               /* Handle open on database file */
    int iRegion,                    /* Region to retrieve */
    int szRegion,                   /* Size of regions */
    int isWrite,                    /* True: Create or find existing mapping, extend file if necessary; False: Find existing mapping */
    volatile void** pp              /* OUT: Mapped memory */
)
{
    Vtl1SqliteFile* pVtl1File = Vtl1FileFromSqliteFile(fd);

    WinShmMapContext context = { 0 };
    context.vtl0File = pVtl1File->vtl0File;
    context.iRegion = iRegion;
    context.szRegion = szRegion;
    context.isWrite = isWrite;

    int rc = CallVtl0VfsFunction<&Vtl0VfsCallbacks::winShmMap>(context);

    *pp = nullptr;              // Must return nullptr on failure.

    // Handler is permitted to return SQLITE_OK and a null pointer
    // (meaning "no existing mapping found"),
    // so do VTL0 validation only if the pointer is non-null.
    if (rc == SQLITE_OK && context.p)
    {
        if (SUCCEEDED(CheckForVTL0Buffer(const_cast<void*>(context.p), szRegion)))
        {
            *pp = context.p;
        }
        else
        {
            SetLastError(ERROR_INTERNAL_ERROR);
            rc = SQLITE_INTERNAL;
        }
    }

    return rc;
}

static int wineShmLock(
    sqlite3_file* fd,          /* Database file holding the shared memory */
    int ofst,                  /* First lock to acquire or release */
    int n,                     /* Number of locks to acquire or release */
    int flags                  /* What to do with the lock */
)
{
    Vtl1SqliteFile* pVtl1File = Vtl1FileFromSqliteFile(fd);

    WinShmLockContext context = { 0 };
    context.vtl0File = pVtl1File->vtl0File;
    context.ofst = ofst;
    context.n = n;
    context.flags = flags;

    int rc = CallVtl0VfsFunction<&Vtl0VfsCallbacks::winShmLock>(context);

    return rc;
}

static void wineShmBarrier(
    sqlite3_file* fd          /* Database holding the shared memory */
)
{
    Vtl1SqliteFile* pVtl1File = Vtl1FileFromSqliteFile(fd);

    WinFileOpContext context = { 0 };
    context.vtl0File = pVtl1File->vtl0File;

    CallVtl0VfsFunction<&Vtl0VfsCallbacks::winShmBarrier>(context);
}

static int wineShmUnmap(
	sqlite3_file* fd,          /* Database holding the shared memory */
	int deleteFlag             /* Delete shared-memory if true */
)
{
    Vtl1SqliteFile* pVtl1File = Vtl1FileFromSqliteFile(fd);

	WinShmUnmapContext context = { 0 };
	context.vtl0File = pVtl1File->vtl0File;
	context.deleteFlag = deleteFlag;

	int rc = CallVtl0VfsFunction<&Vtl0VfsCallbacks::winShmUnmap>(context);

	return rc;
}

#pragma endregion

/*
** This vector defines all the methods that can operate on an
** sqlite3_file for win32.
*/
static sqlite3_io_methods const wineIoMethod = {
    2,                         /* iVersion */
    wineClose,                 /* xClose */
    wineRead,                  /* xRead */
    wineWrite,                 /* xWrite */
    wineTruncate,              /* xTruncate */
    wineSync,                  /* xSync */
    wineFileSize,              /* xFileSize */
    wineLock,                  /* xLock */
    wineUnlock,                /* xUnlock */
    wineCheckReservedLock,     /* xCheckReservedLock */
    wineFileControl,           /* xFileControl */
    0,                         /* xSectorSize */
    wineDeviceCharacteristics, /* xDeviceCharacteristics */
    wineShmMap,                /* xShmMap */
    wineShmLock,               /* xShmLock */
    wineShmBarrier,            /* xShmBarrier */
    wineShmUnmap,              /* xShmUnmap */
    0,                         /* xFetch */
    0                          /* xUnfetch */
};


#pragma region OS_METHODS

/*
** Open a file.
*/
static int wineOpen(
    [[maybe_unused]] sqlite3_vfs* pVfs, /* Used to get maximum path length and AppData */
    char const* zName, /* Name of the file (UTF-8) */
    sqlite3_file* id,  /* Write the SQLite file handle here */
    int flags,         /* Open mode flags */
    int* pOutFlags     /* Status return flags */
)
{
    // SQLite requires that even on failure, pMethods must be be set to nullptr
    // or be set to a valid sqlite3_io_methods that can withstand an xClose.
    // We choose the nullptr so we don't have to do null checks in xClose.
    // Just to be safe, we'll zero out everything.
    Vtl1SqliteFile* pFile = Vtl1FileFromSqliteFile(id);
    ZeroMemory(pFile, sizeof(*pFile));

    int eType = flags & 0xFFFFFF00;  /* Type of file to open */

    WinOpenContext context = {0};
    context.flags = flags;

    int rc = SQLITE_OK;
    if (zName != nullptr)
    {
        size_t nameSize = strlen(zName) + 1;

        if ((eType == SQLITE_OPEN_MAIN_DB) && !(flags & SQLITE_OPEN_URI))
        {
            // Non-URI database files are double-null-terminated.
            nameSize += 1;
        }

        if (nameSize >= ARRAYSIZE(context.zName))
        {
            rc = SQLITE_CANTOPEN;
        }
        else
        {
            memcpy_s(context.zName, sizeof(context.zName), zName, nameSize * sizeof(*zName));
        }
    }
    else
    {
        // nullptr for the name means "create a temporary file".
        // We use an empty string to represent nullptr.
    }

    if (rc == SQLITE_OK)
    {
        rc = CallVtl0VfsFunction<&Vtl0VfsCallbacks::winOpen>(context);
    }
    if (rc == SQLITE_OK)
    {
        // Initialize our file structure enough that we can wineClose it.
        pFile->pMethods = &wineIoMethod;
        pFile->vtl0File = context.vtl0File;

        // Make sure they passed us a valid nonempty buffer.
        if ((context.rwBufferSize > 0) && SUCCEEDED(CheckForVTL0Buffer(context.rwBuffer, context.rwBufferSize)))
        {
            // Save the buffers now that they have been validated.
            pFile->rwBuffer = context.rwBuffer;
            pFile->rwBufferSize = context.rwBufferSize;
        }
        else
        {
            // Internal error: VTL0 was uncooperative. Close the file and fail out.
            wineClose(id);
            SetLastError(ERROR_INTERNAL_ERROR);
            rc = SQLITE_INTERNAL;
        }
    }

    if (pOutFlags != nullptr)
    {
        *pOutFlags = context.outFlags;
    }
    return rc;
}

static int wineDelete(
    [[maybe_unused]] sqlite3_vfs* pVfs,
    char const* zFilename, /* Name of file to delete */
    [[maybe_unused]] int syncDir            /* Not used on win32 */
)
{
    WinDeleteContext context = {0};
    size_t nameSize = strlen(zFilename) + 1;

    int rc = SQLITE_OK;

    if (nameSize > ARRAYSIZE(context.zName))
    {
        // File name too long returns "file not found"
        rc = SQLITE_IOERR_DELETE_NOENT;
    }
    else
    {
        memcpy_s(context.zName, sizeof(context.zName), zFilename, nameSize * sizeof(*zFilename));
        rc = CallVtl0VfsFunction<&Vtl0VfsCallbacks::winDelete>(context);
    }

    return rc;
}

static int wineAccess(
    [[maybe_unused]] sqlite3_vfs* pVfs,
    char const* zFilename, /* Name of file to check */
    int flags,              /* Type of test to make on this file */
    int* pResOut           /* OUT: Result */
)
{
    int rc = SQLITE_OK;

    WinAccessContext context = { 0 };
    context.flags = flags;

    if (zFilename == nullptr)
    {
        // Null pointer file name returns a result of FALSE (no access)
        context.resOut = FALSE;
        rc = SQLITE_OK;
    }
    else if (size_t nameSize = strlen(zFilename) + 1; nameSize > ARRAYSIZE(context.zName))
    {
        // File name too long returns a result of FALSE (no access)
        context.resOut = FALSE;
        rc = SQLITE_OK;
    }
    else
    {
        memcpy_s(context.zName, sizeof(context.zName), zFilename, nameSize * sizeof(*zFilename));
        rc = CallVtl0VfsFunction<&Vtl0VfsCallbacks::winAccess>(context);
    }

    *pResOut = context.resOut;

    return rc;
}

static int wineFullPathname(
    [[maybe_unused]] sqlite3_vfs* pVfs,     /* Pointer to vfs object */
    char const* zRelative, /* Possibly relative input path */
    int nFull,              /* Size of output buffer in bytes */
    char* zFull            /* Output buffer */
)
{
	// Simply passthrough the path. This means this implementation will require
    // full paths to be passed in.
    size_t nameSize = strlen(zRelative) + 1;
    memcpy_s(zFull, nFull, zRelative, nameSize * sizeof(*zRelative));
    
    return SQLITE_OK;
}


/*
** Write up to nBuf bytes of randomness into zBuf.
** No need to shim to the host
*/
static int wineRandomness([[maybe_unused]] sqlite3_vfs* pVfs, int nBuf, char* zBuf)
{
#if defined(SQLITE_TEST) || defined(SQLITE_OMIT_RANDOMNESS)
    memset(zBuf, 0, nBuf);
    return nBuf;
#else
    RtlZeroMemory(zBuf, nBuf);
    HRESULT hr = HRESULT_FROM_NT(BCryptGenRandom(NULL, reinterpret_cast<PUCHAR>(zBuf), nBuf, BCRYPT_USE_SYSTEM_PREFERRED_RNG));
    if (SUCCEEDED(hr))
    {
        return nBuf;
    }

    return 0;
#endif
}

/*
** Sleep for a little while.  Return the amount of time slept.
*/
static int wineSleep([[maybe_unused]] sqlite3_vfs* pVfs, int microsec)
{
    EnclaveSleep(microsec / 1000);
    return microsec;
}

/*
** Find the current time (in Universal Coordinated Time).  Write into *piNow
** the current time and date as a Julian Day number times 86_400_000.  In
** other words, write into *piNow the number of milliseconds since the Julian
** epoch of noon in Greenwich on November 24, 4714 B.C according to the
** proleptic Gregorian calendar.
**
** On success, return SQLITE_OK.  Return SQLITE_ERROR if the time and date
** cannot be found.
*/
static int wineCurrentTimeInt64([[maybe_unused]] sqlite3_vfs* pVfs, sqlite3_int64* piNow)
{
    WinCurrentTimeInt64Context context = {0};
    int rc = CallVtl0VfsFunction<&Vtl0VfsCallbacks::winCurrentTimeInt64>(context);
    *piNow = context.now;

    return rc;
}

/*
** Find the current time (in Universal Coordinated Time).  Write the
** current time and date as a Julian Day number into *prNow and
** return 0.  Return 1 if the time and date cannot be found.
*/
static int wineCurrentTime(sqlite3_vfs* pVfs, double* prNow)
{
    int rc;
    sqlite3_int64 i;
    rc = wineCurrentTimeInt64(pVfs, &i);
    if (rc== SQLITE_OK)
    {
        *prNow = i / 86400000.0;
    }
    return rc;
}

/*
** Return last error code. The error message is not important,
** thus it's ignored.
*/
static int wineGetLastError([[maybe_unused]] sqlite3_vfs* pVfs, [[maybe_unused]] int nBuf, [[maybe_unused]] char* zBuf)
{
    // We pick up the value set by CallVtl0VfsFunction on its way out.
    return static_cast<int>(GetLastError());
}

#pragma endregion

HRESULT ConfigureEnclaveVfsImpl(_In_ VfsConfigParams* vfsConfigParams)
{
    auto guard = g_vtl0VfsCallbackInitLock.lock_exclusive();

    RETURN_HR_IF(HRESULT_FROM_WIN32(ERROR_ALREADY_INITIALIZED), g_vtl0SharedMemory.load(std::memory_order_relaxed) != nullptr);

    // Capture the parameter block from VTL.0.
    VfsConfigParams params{};
    RETURN_IF_FAILED(CopyFromVTL0ToVTL1(&params, vfsConfigParams));

    // Verify that the shared memory buffer resides in VTL.0
    RETURN_IF_FAILED(CheckForVTL0Buffer(params.sharedMemory, sizeof(Vtl0SharedMemoryBuffer) * ENCLAVE_MAX_THREADS));

    // Copy the callback functions from VTL.0. The pointers themselves are validated at use.
    RETURN_IF_FAILED(CopyFromVTL0ToVTL1(&g_vtl0VfsCallbacks, params.vtl0Callbacks));

    // Everything worked: Setting g_vtl0SharedMemory signals that we are initialized.
    // Use release semantics to ensure that the callbacks are visible first.
    g_vtl0SharedMemory.store(params.sharedMemory, std::memory_order_release);

    // Likely sqlite3_initialize has not been called
    // Configure the mutex methods.
    auto mutexMethods = GetEnclaveMutexMethods();
    int rc = sqlite3_config(SQLITE_CONFIG_MUTEX, mutexMethods);
#ifndef NORMAL_MODE
    RETURN_IF_FAILED(HRESULT_FROM_SQLITE_RESULT(rc));
#else
    // The only expected scenario for sqlite3_config(SQLITE_CONFIG_MUTEX,.) to fail is if
    // sqlite3_initialize has already been called. This should only be acceptable in
    // test mode where the Enclave VFS could be coexisting with the full sqlite3 library
    // in the same binary and thus sqlite3_initialize would have been called for the full win
    // sqlite3 version.
    // In that case, make error to configure the mutex methods not hard.
    LOG_IF_FAILED(HRESULT_FROM_SQLITE_RESULT(rc));
#endif
    return S_OK;
}

/*
* This method should be exported by the Enclave dll and called once by the
* host to configure the VFS callbacks. It is not thread safe as it should be
* called only once during initialization.
*/
PVOID WINAPI ConfigureEnclaveVfs(_In_ PVOID vfsConfigParams)
{
    RETURN_HR_AS_PVOID(ConfigureEnclaveVfsImpl(static_cast<VfsConfigParams*>(vfsConfigParams)));
}

int RegisterWin32eVfs()
{
    // Ensure that the callbacks have been initialized.
    // Once initialized, they cannot become uninitialized, 
    // so just checking the pointer is sufficient.
    // Use acquire semantics to ensure the callbacks are ready.
    if (g_vtl0SharedMemory.load(std::memory_order_acquire) == nullptr)
    {
        return SQLITE_ERROR;
    }

    static sqlite3_vfs enclaveVfs = {
        1,                           /* iVersion */
        sizeof(Vtl1SqliteFile),      /* szOsFile */
        SQLITE_WIN32_MAX_PATH_BYTES, /* mxPathname */
        0,                           /* pNext */
        "win32e",                    /* zName */
        0,                           /* pAppData */
        wineOpen,                    /* xOpen */
        wineDelete,                  /* xDelete */
        wineAccess,                  /* xAccess */
        wineFullPathname,            /* xFullPathname */
        0,                           /* xDlOpen */
        0,                           /* xDlError */
        0,                           /* xDlSym */
        0,                           /* xDlClose */
        wineRandomness,              /* xRandomness */
        wineSleep,                   /* xSleep */
        wineCurrentTime,             /* xCurrentTime */
        wineGetLastError,            /* xGetLastError */
        wineCurrentTimeInt64,        /* xCurrentTimeInt64 */
        0,                           /* xSetSystemCall */
        0,                           /* xGetSystemCall */
        0,                           /* xNextSystemCall */
    };

    return sqlite3_vfs_register(&enclaveVfs, TRUE /* make default */);
}
