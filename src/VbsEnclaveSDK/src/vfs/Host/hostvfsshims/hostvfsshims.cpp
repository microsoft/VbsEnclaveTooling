// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "pch.h"
#include <sqlite3.h> // This is the header file for SQLite in the host side
#include <iostream>
#include <cassert>
#include <shared_enclave.h>
#include "enclave_vfs.h"
#include "enclave_vfsp_vtl0.h"
#include "EnclaveHost.h"
#include "veil.any.h"

#define RETURN_SQLITE_RC_AS_PVOID(rc) return (PVOID)((ULONG_PTR)(rc) & 0x000000007FFFFFFF);

sqlite3_vfs* g_builtinWin32Vfs;

// Helper function for VFS callbacks.
// Ensures that the handler function is declared with the correct payload type.
// Calls the handler.
// Captures the last error code when the handler returns.
// Converts the SQLite result code to a PVOID for returning to the enclave.
template<auto mem, auto handler>
PVOID winhDispatchCallback(_In_ PVOID context)
{
    using ContextType = typename Vtl0AssociatedContext<mem>::type;
    static_assert(
        std::is_same_v<int (*)(ContextType*), decltype(handler)>,
        "Handler function passed to winhDispatchCallback does not accept the correct context type.");

    // Static cast first to WinLastErrorContext (what CallVtl0VfsFunctionImpl passes),
    // and then static cast again to the ContextType (to recover what the enclave passed).
    // If ContextType derives from multiple base classes, the second static cast might
    // not be a nop.
    auto lastErrorContext = static_cast<WinLastErrorContext*>(context);
    auto handlerArgs = static_cast<ContextType*>(lastErrorContext);
    auto rc = handler(handlerArgs);

    // use lastErrorContext explicitly (instead of handlerArgs)
    // in case ContextType also has a lastError member.
    lastErrorContext->lastError = GetLastError();
    RETURN_SQLITE_RC_AS_PVOID(rc);
}

int winhOpenImpl(_Inout_ WinOpenContext *args)
{
    auto vtl0File = std::unique_ptr<Vtl0SqliteFile>(
        static_cast<Vtl0SqliteFile*>(operator new(sizeof(Vtl0SqliteFile) + g_builtinWin32Vfs->szOsFile, std::nothrow)));
    if (!vtl0File)
    {
        return SQLITE_NOMEM;
    }

    // SQLite guarantees that the name will be valid until the file is closed.
    // To honor that guarantee, make a copy of the name and give that copy to xOpen.
    memcpy_s(vtl0File->zName, sizeof(vtl0File->zName), args->zName, sizeof(args->zName));

    // Empty string converts to nullptr, which means "create a temporary file".
    char* zName = vtl0File->zName[0] ? vtl0File->zName : nullptr;

    // Ask SQLite's vfs to open the file.
    auto vfsFile = vtl0File->VfsFile();
    int rc = g_builtinWin32Vfs->xOpen(g_builtinWin32Vfs, zName, vfsFile, args->flags, &args->outFlags);

    if (rc == SQLITE_OK)
    {
        // Tell VTL.1 where our buffer is.
        args->rwBuffer = vtl0File->rwBuffer;
        args->rwBufferSize = sizeof(vtl0File->rwBuffer);

        // Transfer ownership to VTL.1.
        args->vtl0File = vtl0File.release();
    }

    return rc;
}

PVOID winhOpen(_Inout_ PVOID context)
{
    return winhDispatchCallback<&Vtl0VfsCallbacks::winOpen, winhOpenImpl>(context);
}

int winhCloseImpl(_Inout_ WinFileOpContext* args)
{
    // Let the Vtl0SqliteFile destructor do the work.
    std::unique_ptr<Vtl0SqliteFile> vtl0File(args->vtl0File);

    return SQLITE_OK;
}

PVOID winhClose(_Inout_ PVOID context)
{
    return winhDispatchCallback<&Vtl0VfsCallbacks::winClose, winhCloseImpl>(context);
}

/*
** Read data from a file into a buffer.  Return SQLITE_OK if all
** bytes were read successfully and SQLITE_IOERR if anything goes
** wrong.
*/
int winhReadImpl(_Inout_ WinRWContext* args)
{
    int rc = SQLITE_OK;

    Vtl0SqliteFile* vtl0File = args->vtl0File;

    if (args->amt > SQLITE_RW_BUFFER_SIZE)
    {
        // Should never happen: Enclave should be honoring our maximum buffer size.
        LOG_HR(E_INVALIDARG);
        rc = SQLITE_IOERR_READ;
    }
    else
    {
        sqlite3_file* id = vtl0File->VfsFile();
        rc = id->pMethods->xRead(id, vtl0File->rwBuffer, args->amt, args->offset);
    }
    return rc;
}

PVOID winhRead(_Inout_ PVOID context)
{
    return winhDispatchCallback<&Vtl0VfsCallbacks::winRead, winhReadImpl>(context);
}

int winhFileSizeImpl(_Inout_ WinFileSizeContext* args)
{
    sqlite3_file* id = args->vtl0File->VfsFile();
    int rc = id->pMethods->xFileSize(id, &args->size);

    return rc;    
}

PVOID winhFileSize(_Inout_ PVOID context)
{
    return winhDispatchCallback<&Vtl0VfsCallbacks::winFileSize, winhFileSizeImpl>(context);
}

int winhLockImpl(_Inout_ WinLockContext* args)
{
    sqlite3_file* id = args->vtl0File->VfsFile();
    int rc = id->pMethods->xLock(id, args->locktype);

    return rc;
}

PVOID winhLock(_Inout_ PVOID context)
{
    return winhDispatchCallback<&Vtl0VfsCallbacks::winLock, winhLockImpl>(context);
}

int winhUnlockImpl(_Inout_ WinLockContext* args)
{
    sqlite3_file* id = args->vtl0File->VfsFile();
    int rc = id->pMethods->xUnlock(id, args->locktype);

    return rc;
}

PVOID winhUnlock(_Inout_ PVOID context)
{
    return winhDispatchCallback<&Vtl0VfsCallbacks::winUnlock, winhUnlockImpl>(context);
}

int winhCheckReservedLockImpl(_Inout_ WinCheckReservedLock* args)
{
    sqlite3_file* id = args->vtl0File->VfsFile();

    int rc = id->pMethods->xCheckReservedLock(id, &args->result);

    return rc;
}

PVOID winhCheckReservedLock(_Inout_ PVOID context)
{
    return winhDispatchCallback<&Vtl0VfsCallbacks::winCheckReservedLock, winhCheckReservedLockImpl>(context);
}

int winhFileControlImpl(_Inout_ WinFileControl* args)
{
    sqlite3_file* id = args->vtl0File->VfsFile();

    int rc = id->pMethods->xFileControl(id, args->op, &args->data);

    return rc;
}

PVOID winhFileControl(_Inout_ PVOID context)
{
    return winhDispatchCallback<&Vtl0VfsCallbacks::winFileControl, winhFileControlImpl>(context);
}

int winhAccessImpl(_Inout_ WinAccessContext* args)
{
    int rc = g_builtinWin32Vfs->xAccess(g_builtinWin32Vfs, args->zName, args->flags, &args->resOut);

    return rc;
}

PVOID winhAccess(_Inout_ PVOID context)
{
    return winhDispatchCallback<&Vtl0VfsCallbacks::winAccess, winhAccessImpl>(context);
}

int winhCurrentTimeInt64Impl(_Inout_ WinCurrentTimeInt64Context* args)
{
    int rc = g_builtinWin32Vfs->xCurrentTimeInt64(g_builtinWin32Vfs, &args->now);

    return rc;
}

PVOID winhCurrentTimeInt64(_Inout_ PVOID context)
{
    return winhDispatchCallback<&Vtl0VfsCallbacks::winCurrentTimeInt64, winhCurrentTimeInt64Impl>(context);
}

int winhWriteImpl(_Inout_ WinRWContext* args)
{
    int rc = SQLITE_OK;

    Vtl0SqliteFile* vtl0File = args->vtl0File;

    if (args->amt > SQLITE_RW_BUFFER_SIZE)
    {
        // Should never happen: Enclave should be honoring our maximum buffer size.
        LOG_HR(E_INVALIDARG);
        rc = SQLITE_IOERR_WRITE;
    }
    else
    {
        sqlite3_file* id = vtl0File->VfsFile();
        rc = id->pMethods->xWrite(id, vtl0File->rwBuffer, args->amt, args->offset);
    }
    return rc;
}

PVOID winhWrite(_Inout_ PVOID context)
{
    return winhDispatchCallback<&Vtl0VfsCallbacks::winWrite, winhWriteImpl>(context);
}

int winhDeleteImpl(_Inout_ WinDeleteContext* args)
{
    int rc = g_builtinWin32Vfs->xDelete(g_builtinWin32Vfs, args->zName, 0);

    return rc;
}

PVOID winhDelete(_Inout_ PVOID context)
{
    return winhDispatchCallback<&Vtl0VfsCallbacks::winDelete, winhDeleteImpl>(context);
}


int winhTruncateImpl(_Inout_ WinTruncateContext* args)
{
    sqlite3_file* id = args->vtl0File->VfsFile();
    int rc = id->pMethods->xTruncate(id, args->size);

    return rc;
}

PVOID winhTruncate(_Inout_ PVOID context)
{
    return winhDispatchCallback<&Vtl0VfsCallbacks::winTruncate, winhTruncateImpl>(context);
}

int winhSyncImpl(_Inout_ WinSyncContext* args)
{
    sqlite3_file* id = args->vtl0File->VfsFile();
	int rc = id->pMethods->xSync(id, args->flags);

    return rc;
}

PVOID winhSync(_Inout_ PVOID context)
{
    return winhDispatchCallback<&Vtl0VfsCallbacks::winSync, winhSyncImpl>(context);
}

int winhDeviceCharacteristicsImpl(_Inout_ WinDeviceCharacteristics* args)
{
    sqlite3_file* id = args->vtl0File->VfsFile();
    args->result = id->pMethods->xDeviceCharacteristics(id);

    return SQLITE_OK;
}

PVOID winhDeviceCharacteristics(_Inout_ PVOID context)
{
    return winhDispatchCallback<&Vtl0VfsCallbacks::winDeviceCharacteristics, winhDeviceCharacteristicsImpl>(context);
}

int winhShmMapImpl(_Inout_ WinShmMapContext* args)
{
    sqlite3_file* fd = args->vtl0File->VfsFile();
	int rc = fd->pMethods->xShmMap(fd, args->iRegion, args->szRegion, args->isWrite, &args->p);
    
	return rc;
}

PVOID winhShmMap(_Inout_ PVOID context)
{
    return winhDispatchCallback<&Vtl0VfsCallbacks::winShmMap, winhShmMapImpl>(context);
}

int winhShmLockImpl(_Inout_ WinShmLockContext* args)
{
	sqlite3_file* fd = args->vtl0File->VfsFile();
	int rc = fd->pMethods->xShmLock(fd, args->ofst, args->n, args->flags);

	return rc;
}

PVOID winhShmLock(_Inout_ PVOID context)
{
    return winhDispatchCallback<&Vtl0VfsCallbacks::winShmLock, winhShmLockImpl>(context);
}

int winhShmBarrierImpl(_Inout_ WinFileOpContext* args)
{
    sqlite3_file* fd = args->vtl0File->VfsFile();

    // xShmBarrier has no return value.
    fd->pMethods->xShmBarrier(fd);

	return SQLITE_OK;
}

PVOID winhShmBarrier(_Inout_ PVOID context)
{
    return winhDispatchCallback<&Vtl0VfsCallbacks::winShmBarrier, winhShmBarrierImpl>(context);
}

int winhShmUnmapImpl(_Inout_ WinShmUnmapContext* args)
{
	sqlite3_file* fd = args->vtl0File->VfsFile();
	int rc = fd->pMethods->xShmUnmap(fd, args->deleteFlag);

	return rc;
}

PVOID winhShmUnmap(_Inout_ PVOID context)
{
    return winhDispatchCallback<&Vtl0VfsCallbacks::winShmUnmap, winhShmUnmapImpl>(context);
}

HRESULT SetupEnclaveSqliteVfs(Enclave& enclave) try
{
    PENCLAVE_ROUTINE configureVfs = enclave.GetEnclaveRoutine("ConfigureEnclaveVfs");
    
    // This should register the standard VFS for windows in the host side
    sqlite3_initialize();

    // Now go find it so we can forward to it.
    g_builtinWin32Vfs = sqlite3_vfs_find("win32");
    RETURN_HR_IF_NULL(E_UNEXPECTED, g_builtinWin32Vfs);

    static constexpr Vtl0VfsCallbacks vfsCallbacks = {
        .winOpen = winhOpen,
        .winClose = winhClose,
        .winRead = winhRead,
        .winFileSize = winhFileSize,
        .winLock = winhLock,
        .winUnlock = winhUnlock,
        .winAccess = winhAccess,
        .winCurrentTimeInt64 = winhCurrentTimeInt64,
        .winWrite = winhWrite,
        .winCheckReservedLock = winhCheckReservedLock,
        .winFileControl = winhFileControl,
        .winDelete = winhDelete,
        .winTruncate = winhTruncate,
        .winSync = winhSync,
        .winDeviceCharacteristics = winhDeviceCharacteristics,
        .winShmMap = winhShmMap,
        .winShmLock = winhShmLock,
        .winShmBarrier = winhShmBarrier,
        .winShmUnmap = winhShmUnmap,
    };

    // Preallocated shared memory buffer for param passing from VTL.1 to VTL.0
    auto sharedMemBuffer = std::make_unique_for_overwrite<Vtl0SharedMemoryBuffer[]>(ENCLAVE_MAX_THREADS);

    VfsConfigParams vfsConfigParams = { 0 };
    vfsConfigParams.vtl0Callbacks = &vfsCallbacks;
    vfsConfigParams.sharedMemory = sharedMemBuffer.get();

    PVOID retVal;
    RETURN_IF_FAILED(enclave.CallWithResult(configureVfs, &vfsConfigParams, &retVal));
    RETURN_IF_FAILED(PVOID_TO_HRESULT(retVal));

    // This memory is now owned by VTL.1.
    sharedMemBuffer.release();

    return S_OK;
}
CATCH_RETURN()

