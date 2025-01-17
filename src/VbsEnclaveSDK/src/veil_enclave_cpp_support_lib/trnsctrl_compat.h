// © Microsoft Corporation. All rights reserved.

#pragma once

#include <ehdata.h>

__declspec(guard(ignore)) inline void __stdcall _CallMemberFunction0(void * const pthis, void * const pmfn) noexcept(false)
{
    auto const OneArgFn = reinterpret_cast<void(__thiscall *)(void *)>(pmfn);
    OneArgFn(pthis);
}

__declspec(guard(ignore)) inline void __stdcall _CallMemberFunction1(void * const pthis, void * const pmfn, void * const pthat) noexcept(false)
{
    auto const TwoArgFn = reinterpret_cast<void(__thiscall *)(void *, void *)>(pmfn);
    TwoArgFn(pthis, pthat);
}

__declspec(guard(ignore)) inline void __stdcall _CallMemberFunction2(
    void * const pthis,
    void * const pmfn,
    void * const pthat,
    int const val2) noexcept(false)
{
    auto const ThreeArgFn = reinterpret_cast<void(__thiscall *)(void *, void *, int)>(pmfn);
    ThreeArgFn(pthis, pthat, val2);
}

typedef void(__stdcall * PFNPREPARE_FOR_THROW)(void * ExceptionInfo);

typedef struct WinRTExceptionInfo
{
    void * description;
    void * restrictedErrorString;
    void * restrictedErrorReference;
    void * capabilitySid;
    long hr;
    void * restrictedInfo;
    ThrowInfo * throwInfo;
    unsigned int size;
    PFNPREPARE_FOR_THROW PrepareThrow;
} WINRTEXCEPTIONINFO;

extern "C" _VCRTIMP void ** __cdecl __current_exception();
extern "C" _VCRTIMP void ** __cdecl __current_exception_context();
extern "C" _VCRTIMP int * __cdecl __processing_throw();



#define _pCurrentException (*reinterpret_cast<EHExceptionRecord **>(__current_exception()))
#define _pCurrentExContext (*reinterpret_cast<CONTEXT **>(__current_exception_context()))
#define __ProcessingThrow (*__processing_throw())
