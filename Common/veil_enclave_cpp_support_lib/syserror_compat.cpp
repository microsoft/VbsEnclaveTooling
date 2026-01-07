#include "pch.h"
namespace std
{
    _CRTIMP2_PURE const char * __CLRCALL_PURE_OR_CDECL _Syserror_map(int _Errcode)
    {
        UNREFERENCED_PARAMETER(_Errcode);
        return "unknown error";
    }

    _CRTIMP2_PURE int __CLRCALL_PURE_OR_CDECL _Winerror_map(int _Errcode)
    {
        UNREFERENCED_PARAMETER(_Errcode);
        return 0;
    }
}

extern "C"
{
    size_t __std_system_error_allocate_message(unsigned long _Message_id, char ** _Ptr_str) noexcept
    {
        UNREFERENCED_PARAMETER(_Message_id);
        UNREFERENCED_PARAMETER(_Ptr_str);
        return 0;
    }

    void __std_system_error_deallocate_message(char * buffer) noexcept
    {
        if (buffer)
        {
            delete buffer;
        }
    }
}
