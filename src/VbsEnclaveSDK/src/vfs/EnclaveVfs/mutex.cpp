// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "pch.h"
#include <sqlite3.h>
#include "enclave_vfs.h"
#include "enclave_vfsp.h"
#include "EnclaveServices.h"

// The code in this file is a slightly modified version of the code in sqlite3.c
// to define the win32 mutex behavior

#define ArraySize(X)    ARRAYSIZE(X)

#ifdef _DEBUG
#define SQLITE_DEBUG
#endif

/*
** The code in this file is only used if we are compiling multithreaded
** on a Win32 system.
*/


/*
** Each recursive mutex is an instance of the following structure.
*/
struct sqlite3_mutex {
    CRITICAL_SECTION mutex;    /* Mutex controlling the lock */
    int id;                    /* Mutex type */
#ifdef SQLITE_DEBUG
    volatile int nRef;         /* Number of entrances */
    volatile DWORD owner;      /* Thread holding this mutex */
    volatile LONG trace;       /* True to trace changes */
#endif
};

void EnclaveSleep(DWORD milliseconds)
{
    CONDITION_VARIABLE cv;
    SRWLOCK lock;
    InitializeConditionVariable(&cv);
    InitializeSRWLock(&lock);

    AcquireSRWLockExclusive(&lock);
    SleepConditionVariableSRW(&cv, &lock, milliseconds, 0);
    ReleaseSRWLockExclusive(&lock);
}

SQLITE_API void sqlite3_win32_sleep(DWORD milliseconds)
{
    EnclaveSleep(milliseconds);
}

/*
** These are the initializer values used when declaring a "static" mutex
** on Win32.  It should be noted that all mutexes require initialization
** on the Win32 platform.
*/
#define SQLITE_W32_MUTEX_INITIALIZER { 0 }

#ifdef SQLITE_DEBUG
#define SQLITE3_MUTEX_INITIALIZER(id) { SQLITE_W32_MUTEX_INITIALIZER, id, \
                                    0L, (DWORD)0, 0 }
#else
#define SQLITE3_MUTEX_INITIALIZER(id) { SQLITE_W32_MUTEX_INITIALIZER, id }
#endif

#ifdef SQLITE_DEBUG
/*
** The sqlite3_mutex_held() and sqlite3_mutex_notheld() routine are
** intended for use only inside assert() statements.
*/
static int wineMutexHeld(sqlite3_mutex* p)
{
    return p->nRef != 0 && p->owner == GetCurrentThreadId();
}

static int wineMutexNotheld2(sqlite3_mutex* p, DWORD tid)
{
    return p->nRef == 0 || p->owner != tid;
}

static int wineMutexNotheld(sqlite3_mutex* p)
{
    DWORD tid = GetCurrentThreadId();
    return wineMutexNotheld2(p, tid);
}
#endif

/*
** Initialize and deinitialize the mutex subsystem.
*/
static sqlite3_mutex wineMutex_staticMutexes[] = {
  SQLITE3_MUTEX_INITIALIZER(2),
  SQLITE3_MUTEX_INITIALIZER(3),
  SQLITE3_MUTEX_INITIALIZER(4),
  SQLITE3_MUTEX_INITIALIZER(5),
  SQLITE3_MUTEX_INITIALIZER(6),
  SQLITE3_MUTEX_INITIALIZER(7),
  SQLITE3_MUTEX_INITIALIZER(8),
  SQLITE3_MUTEX_INITIALIZER(9),
  SQLITE3_MUTEX_INITIALIZER(10),
  SQLITE3_MUTEX_INITIALIZER(11),
  SQLITE3_MUTEX_INITIALIZER(12),
  SQLITE3_MUTEX_INITIALIZER(13)
};

static int wineMutex_isInit = 0;
static int wineMutex_isNt = -1; /* <0 means "need to query" */

/* As the winMutexInit() and winMutexEnd() functions are called as part
** of the sqlite3_initialize() and sqlite3_shutdown() processing, the
** "interlocked" magic used here is probably not strictly necessary.
*/
static LONG volatile wineMutex_lock = 0;

SQLITE_API int sqlite3_win32_is_nt(void); /* os_win.c */
SQLITE_API void sqlite3_win32_sleep(DWORD milliseconds); /* os_win.c */

static int wineMutexInit(void)
{
    /* The first to increment to 1 does actual initialization */
    if (InterlockedCompareExchange(&wineMutex_lock, 1, 0) == 0)
    {
        int i;
        for (i = 0; i < ArraySize(wineMutex_staticMutexes); i++)
        {
            InitializeCriticalSection(&wineMutex_staticMutexes[i].mutex);
        }
        wineMutex_isInit = 1;
    }
    else
    {
        /* Another thread is (in the process of) initializing the static
        ** mutexes */
        while (!wineMutex_isInit)
        {
            sqlite3_win32_sleep(1);
        }
    }
    return SQLITE_OK;
}

static int wineMutexEnd(void)
{
    /* The first to decrement to 0 does actual shutdown
    ** (which should be the last to shutdown.) */
    if (InterlockedCompareExchange(&wineMutex_lock, 0, 1) == 1)
    {
        if (wineMutex_isInit == 1)
        {
            int i;
            for (i = 0; i < ArraySize(wineMutex_staticMutexes); i++)
            {
                DeleteCriticalSection(&wineMutex_staticMutexes[i].mutex);
            }
            wineMutex_isInit = 0;
        }
    }
    return SQLITE_OK;
}

/*
** The sqlite3_mutex_alloc() routine allocates a new
** mutex and returns a pointer to it.  If it returns NULL
** that means that a mutex could not be allocated.  SQLite
** will unwind its stack and return an error.  The argument
** to sqlite3_mutex_alloc() is one of these integer constants:
**
** <ul>
** <li>  SQLITE_MUTEX_FAST
** <li>  SQLITE_MUTEX_RECURSIVE
** <li>  SQLITE_MUTEX_STATIC_MAIN
** <li>  SQLITE_MUTEX_STATIC_MEM
** <li>  SQLITE_MUTEX_STATIC_OPEN
** <li>  SQLITE_MUTEX_STATIC_PRNG
** <li>  SQLITE_MUTEX_STATIC_LRU
** <li>  SQLITE_MUTEX_STATIC_PMEM
** <li>  SQLITE_MUTEX_STATIC_APP1
** <li>  SQLITE_MUTEX_STATIC_APP2
** <li>  SQLITE_MUTEX_STATIC_APP3
** <li>  SQLITE_MUTEX_STATIC_VFS1
** <li>  SQLITE_MUTEX_STATIC_VFS2
** <li>  SQLITE_MUTEX_STATIC_VFS3
** </ul>
**
** The first two constants cause sqlite3_mutex_alloc() to create
** a new mutex.  The new mutex is recursive when SQLITE_MUTEX_RECURSIVE
** is used but not necessarily so when SQLITE_MUTEX_FAST is used.
** The mutex implementation does not need to make a distinction
** between SQLITE_MUTEX_RECURSIVE and SQLITE_MUTEX_FAST if it does
** not want to.  But SQLite will only request a recursive mutex in
** cases where it really needs one.  If a faster non-recursive mutex
** implementation is available on the host platform, the mutex subsystem
** might return such a mutex in response to SQLITE_MUTEX_FAST.
**
** The other allowed parameters to sqlite3_mutex_alloc() each return
** a pointer to a static preexisting mutex.  Six static mutexes are
** used by the current version of SQLite.  Future versions of SQLite
** may add additional static mutexes.  Static mutexes are for internal
** use by SQLite only.  Applications that use SQLite mutexes should
** use only the dynamic mutexes returned by SQLITE_MUTEX_FAST or
** SQLITE_MUTEX_RECURSIVE.
**
** Note that if one of the dynamic mutex parameters (SQLITE_MUTEX_FAST
** or SQLITE_MUTEX_RECURSIVE) is used then sqlite3_mutex_alloc()
** returns a different mutex on every call.  But for the static
** mutex types, the same mutex is returned on every call that has
** the same type number.
*/
static sqlite3_mutex* wineMutexAlloc(int iType)
{
    sqlite3_mutex* p;

    switch (iType)
    {
    case SQLITE_MUTEX_FAST:
    case SQLITE_MUTEX_RECURSIVE:
    {
        p = (sqlite3_mutex*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*p));
        if (p)
        {
            p->id = iType;
            InitializeCriticalSection(&p->mutex);
        }
        break;
    }
    default:
    {
        p = &wineMutex_staticMutexes[iType - 2];
        break;
    }
    }
    assert(p == 0 || p->id == iType);
    return p;
}


/*
** This routine deallocates a previously
** allocated mutex.  SQLite is careful to deallocate every
** mutex that it allocates.
*/
static void wineMutexFree(sqlite3_mutex* p)
{
    assert(p);
    assert(p->nRef == 0 && p->owner == 0);
    if (p->id == SQLITE_MUTEX_FAST || p->id == SQLITE_MUTEX_RECURSIVE)
    {
        DeleteCriticalSection(&p->mutex);
        HeapFree(GetProcessHeap(), 0, p);
    }
}

/*
** The sqlite3_mutex_enter() and sqlite3_mutex_try() routines attempt
** to enter a mutex.  If another thread is already within the mutex,
** sqlite3_mutex_enter() will block and sqlite3_mutex_try() will return
** SQLITE_BUSY.  The sqlite3_mutex_try() interface returns SQLITE_OK
** upon successful entry.  Mutexes created using SQLITE_MUTEX_RECURSIVE can
** be entered multiple times by the same thread.  In such cases the,
** mutex must be exited an equal number of times before another thread
** can enter.  If the same thread tries to enter any other kind of mutex
** more than once, the behavior is undefined.
*/
static void wineMutexEnter(sqlite3_mutex* p)
{
    // If this fails, then some VTL0 code tried to cause trouble by
    // calling back into the DB while inside a VTL0 callout.
    FAIL_FAST_IF(GetThreadEnclaveCalloutCount_NoLogging() != 0);
#if defined(SQLITE_DEBUG) || defined(SQLITE_TEST)
    DWORD tid = GetCurrentThreadId();
#endif
#ifdef SQLITE_DEBUG
    assert(p);
    assert(p->id == SQLITE_MUTEX_RECURSIVE || wineMutexNotheld2(p, tid));
#else
    assert(p);
#endif
    assert(wineMutex_isInit == 1);
    EnterCriticalSection(&p->mutex);
#ifdef SQLITE_DEBUG
    assert(p->nRef > 0 || p->owner == 0);
    p->owner = tid;
    p->nRef++;
#endif
}

static int wineMutexTry(sqlite3_mutex* p)
{
    // If this fails, then some VTL0 code tried to cause trouble by
    // calling back into the DB while inside a VTL0 callout.
    FAIL_FAST_IF(GetThreadEnclaveCalloutCount_NoLogging() != 0);
#if defined(SQLITE_DEBUG) || defined(SQLITE_TEST)
    DWORD tid = GetCurrentThreadId();
#endif
    int rc = SQLITE_BUSY;
    assert(p);
    assert(p->id == SQLITE_MUTEX_RECURSIVE || wineMutexNotheld2(p, tid));
    /*
    ** The sqlite3_mutex_try() routine is very rarely used, and when it
    ** is used it is merely an optimization.  So it is OK for it to always
    ** fail.
    **
    ** The TryEnterCriticalSection() interface is only available on WinNT.
    ** And some windows compilers complain if you try to use it without
    ** first doing some #defines that prevent SQLite from building on Win98.
    ** For that reason, we will omit this optimization for now.  See
    ** ticket #2685.
    */
#if defined(_WIN32_WINNT) && _WIN32_WINNT >= 0x0400
    assert(wineMutex_isInit == 1);
    assert(wineMutex_isNt >= -1 && wineMutex_isNt <= 1);
    if (wineMutex_isNt < 0)
    {
        //winMutex_isNt = sqlite3_win32_is_nt();
        wineMutex_isNt = 1;
    }
    assert(wineMutex_isNt == 0 || wineMutex_isNt == 1);
    if (wineMutex_isNt && TryEnterCriticalSection(&p->mutex))
    {
#ifdef SQLITE_DEBUG
        p->owner = tid;
        p->nRef++;
#endif
        rc = SQLITE_OK;
    }
#else
    UNUSED_PARAMETER(p);
#endif
    return rc;
}

/*
** The sqlite3_mutex_leave() routine exits a mutex that was
** previously entered by the same thread.  The behavior
** is undefined if the mutex is not currently entered or
** is not currently allocated.  SQLite will never do either.
*/
static void wineMutexLeave(sqlite3_mutex* p)
{
#if defined(SQLITE_DEBUG) || defined(SQLITE_TEST)
    DWORD tid = GetCurrentThreadId();
#endif
    assert(p);
#ifdef SQLITE_DEBUG
    assert(p->nRef > 0);
    assert(p->owner == tid);
    p->nRef--;
    if (p->nRef == 0) p->owner = 0;
    assert(p->nRef == 0 || p->id == SQLITE_MUTEX_RECURSIVE);
#endif
    assert(wineMutex_isInit == 1);
    LeaveCriticalSection(&p->mutex);
}

sqlite3_mutex_methods const* GetEnclaveMutexMethods(void)
{
    static const sqlite3_mutex_methods sMutex = {
      wineMutexInit,
      wineMutexEnd,
      wineMutexAlloc,
      wineMutexFree,
      wineMutexEnter,
      wineMutexTry,
      wineMutexLeave,
  #ifdef SQLITE_DEBUG
      wineMutexHeld,
      wineMutexNotheld
  #else
      0,
      0
  #endif
    };
    return &sMutex;
}

