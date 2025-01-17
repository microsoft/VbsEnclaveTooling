// © Microsoft Corporation. All rights reserved.

#include "pch.h"
#include <stdexcept>
#include <functional>

// C shims
inline BOOL IsDebuggerPresent()
{
    return FALSE;
}

inline DWORD FormatMessageW(...)
{
    return 0;
}

#if _DEBUG
_ACRTIMP void __cdecl _invalid_parameter(
    _In_opt_z_ wchar_t const*, _In_opt_z_ wchar_t const*, _In_opt_z_ wchar_t const*, _In_ unsigned int, _In_ uintptr_t)
{
    FAIL_FAST();
}

_ACRTIMP int __cdecl _CrtDbgReport(_In_ int, _In_opt_z_ char const*, _In_ int, _In_opt_z_ char const*, _In_opt_z_ char const*, ...)
{
    return 0;
}
#endif

extern "C++"
// C++ shims
namespace std
{
    __declspec(noreturn) void __cdecl _Xlength_error(_In_z_ const char* msg)
    {
        throw std::length_error(msg);
    }

    __declspec(noreturn) void __cdecl _Xout_of_range(_In_z_ const char* msg)
    {
        throw std::out_of_range(msg);
    }

    __declspec(noreturn) void __cdecl _Xbad_function_call()
    {
        throw std::bad_function_call();
    }

#if _DEBUG
    _Lockit::_Lockit(int lock) noexcept : _Locktype(lock)
    {
    }

    _Lockit::~_Lockit() noexcept
    {
    }
#endif
}

wil::srwlock g_initOnceSrwLock;

#define RunOnceCompleted ((DWORD_PTR)0x1)
#define RunOncePending ((DWORD_PTR)0x2)

_Use_decl_annotations_
BOOL InitOnceBeginInitializeEnclave(
    LPINIT_ONCE lpInitOnce,
    DWORD dwFlags,
    PBOOL fPending,
    LPVOID* lpContext)
{
    auto lock = g_initOnceSrwLock.lock_exclusive();

    // This is a very dumb init-once method. The real one is very clever about interlocke exchanges
    // to be lock-free and racy-init. We're going the simple route since the enclave really only has
    // a small number of actual threads operating in it.

    const auto controlFlags = RunOnceCompleted | RunOncePending;
    auto flags = ((DWORD_PTR)lpInitOnce->Ptr) & controlFlags;

    // All done, report the result of the once-init to the caller and indicate that it's no longer
    // pending completion.
    if (flags & RunOnceCompleted)
    {
        *fPending = FALSE;
        wil::assign_to_opt_param(lpContext, (PVOID)(((DWORD_PTR)lpInitOnce->Ptr) & ~controlFlags));
        return TRUE;
    }

    // For checking state, report whether the operation has completed.
    if (dwFlags & INIT_ONCE_CHECK_ONLY)
    {
        if (flags & RunOncePending)
        {
            // The operation is still pending, so we'll report that to the caller and not change the state.
            *fPending = TRUE;
            wil::assign_null_to_opt_param(lpContext);
            return TRUE;
        }
        else
        {
            // The operation has neither been started nor is it pending.
            *fPending = FALSE;
            wil::assign_null_to_opt_param(lpContext);
            return FALSE;
        }
    }

    // If an operation is pending, wait for it by dropping the lock and doing the
    // WaitOnAddress thing in a loop.
    if (flags & RunOncePending)
    {
        while (flags & RunOncePending)
        {
            lock.reset();
            ::WaitOnAddress(&lpInitOnce->Ptr, &flags, sizeof(PVOID), 50);
            lock = g_initOnceSrwLock.lock_exclusive();
            flags = ((DWORD_PTR)lpInitOnce->Ptr) & controlFlags;
        }

        // The operation has completed, so we'll report that to the caller and not change the state.
        *fPending = FALSE;
        wil::assign_to_opt_param(lpContext, (PVOID)(((DWORD_PTR)lpInitOnce->Ptr) & ~controlFlags));
        return TRUE;
    }
    else
    {
        // This thread won the init race. Set the pending flag and tell the caller they can
        // do their thing.
        *fPending = TRUE;
        wil::assign_null_to_opt_param(lpContext);
        lpInitOnce->Ptr = (PVOID)(RunOncePending | (DWORD_PTR)lpInitOnce->Ptr);
        return TRUE;
    }
}

_Use_decl_annotations_
BOOL InitOnceCompleteEnclave(LPINIT_ONCE lpInitOnce, DWORD dwFlags, LPVOID lpContext)
{
    auto lock = g_initOnceSrwLock.lock_exclusive();

    // This is a very dumb init-once method. The real one is very clever about interlocke exchanges
    // to be lock-free and racy-init. We're going the simple route since the enclave really only has
    // a small number of actual threads operating in it.

    const auto controlFlags = RunOnceCompleted | RunOncePending;
    auto flags = ((DWORD_PTR)lpInitOnce->Ptr) & controlFlags;

    // If the operation is already completed or is not pending, that's a bug...
    if ((flags & RunOncePending) == 0)
    {
        return FALSE;
    }

    // On failure, clear all the bits of the state. On success, set the completion bit and store the
    // context pointer. Wake all waiters to observe this state.
    if (dwFlags & INIT_ONCE_INIT_FAILED)
    {
        lpInitOnce->Ptr = nullptr;
    }
    else
    {
        lpInitOnce->Ptr = (PVOID)(RunOnceCompleted | (DWORD_PTR)lpContext);
    }

    ::WakeByAddressAll(&lpInitOnce->Ptr);
    return TRUE;
}
