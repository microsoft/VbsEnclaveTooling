// © Microsoft Corporation. All rights reserved.

#include "pch.h"
extern "C"
{
    // atomic_wait.cpp
    void _Assume_timeout() noexcept
    {
#ifdef _DEBUG
        if (GetLastError() != ERROR_TIMEOUT)
        {
            ::abort();
        }
#endif // defined(_DEBUG)
    }

    void __stdcall __std_atomic_notify_all_direct(void const * const _Storage) noexcept
    {
        WakeByAddressAll(const_cast<void *>(_Storage));
    }

    int __stdcall __std_atomic_wait_direct(
        void const * const _Storage,
        void * const _Comparand,
        size_t const _Size,
        unsigned long const _Remaining_timeout) noexcept
    {
        auto const _Result =
            WaitOnAddress(const_cast<void volatile *>(_Storage), const_cast<void *>(_Comparand), _Size, _Remaining_timeout);
        if (!_Result)
        {
            _Assume_timeout();
        }
        return _Result;
    }

    void __stdcall __std_atomic_notify_one_direct(void const * const _Storage) noexcept
    {
        WakeByAddressSingle(const_cast<void *>(_Storage));
    }
} // extern
