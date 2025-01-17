// <copyright placeholder>

#pragma once

// Redirect tracelogging's macros to an enclave helper that routes them towards the real thing

#define TLG_HAVE_EVENT_SET_INFORMATION 1
#define TLG_EVENT_REGISTER TlgEnclaveEventRegister
#define TLG_EVENT_UNREGISTER TlgEnclaveEventUnregister
#define TLG_EVENT_WRITE_EX TlgEnclaveEventWriteEx
#define TLG_EVENT_WRITE_TRANSFER TlgEnclaveEventWriteTransfer
#define TLG_EVENT_SET_INFORMATION TlgEnclaveEventSetInformation

// This header configures WIL's headers for use by an enclave. It turns off all the static-init
// support that pulls in Kernelbase/NTDLL methods and replaces FormatMessageW and IsDebuggerPresent
// via macro-mocking.

#ifdef FORMAT_MESSAGE_ALLOCATE_BUFFER
#error "This header must be included before any Windows headers"
#endif

#ifndef RESULT_SUPPRESS_STATIC_INITIALIZERS
#define RESULT_SUPPRESS_STATIC_INITIALIZERS
#endif

#define FormatMessageW DO_NOT_USE_FormatMessageW
#define IsDebuggerPresent DO_NOT_USE_IsDebuggerPresent
#include <winenclave.h>
#include <evntprov.h>
#include <wchar.h>
#undef FormatMessageW
#undef IsDebuggerPresent

extern "C" BOOL IsDebuggerPresent();
extern "C" DWORD FormatMessageW(...);

ULONG
TlgEnclaveEventRegister(_In_ LPCGUID ProviderId, _In_opt_ PENABLECALLBACK EnableCallback, _In_opt_ PVOID CallbackContext, _Out_ PREGHANDLE RegHandle);

ULONG
TlgEnclaveEventUnregister(_In_ REGHANDLE RegHandle);

ULONG
TlgEnclaveEventWriteEx(
    _In_ REGHANDLE RegHandle,
    _In_ PCEVENT_DESCRIPTOR EventDescriptor,
    _In_ ULONG64 Filter,
    _In_ ULONG Flags,
    _In_opt_ LPCGUID ActivityId,
    _In_opt_ LPCGUID RelatedActivityId,
    _In_range_(0, MAX_EVENT_DATA_DESCRIPTORS) ULONG UserDataCount,
    _In_reads_opt_(UserDataCount) PEVENT_DATA_DESCRIPTOR UserData);

ULONG
TlgEnclaveEventWriteTransfer(
    _In_ REGHANDLE RegHandle,
    _In_ PCEVENT_DESCRIPTOR EventDescriptor,
    _In_opt_ LPCGUID ActivityId,
    _In_opt_ LPCGUID RelatedActivityId,
    _In_range_(0, MAX_EVENT_DATA_DESCRIPTORS) ULONG UserDataCount,
    _In_reads_opt_(UserDataCount) PEVENT_DATA_DESCRIPTOR UserData);

ULONG
TlgEnclaveEventSetInformation(
    _In_ REGHANDLE RegHandle,
    _In_ EVENT_INFO_CLASS InformationClass,
    _In_reads_bytes_(InformationLength) PVOID EventInformation,
    _In_ ULONG InformationLength);

#define EventActivityIdControl EventActivityIdControl_Redirected

ULONG
EventActivityIdControl_Redirected(_In_ ULONG ControlCode, _Inout_ LPGUID ActivityId);

// Used by WIL to call methods in NTDLL
#define GetModuleHandleW GetModuleHandle_Redirected

HMODULE GetModuleHandle_Redirected(_In_opt_ LPCWSTR lpModuleName);

#include <TraceLoggingActivity.h>

#include <wil/result_macros.h>
#include <wil/Resource.h>

#define InitOnceBeginInitialize InitOnceBeginInitializeEnclave
#define InitOnceComplete InitOnceCompleteEnclave

BOOL InitOnceBeginInitializeEnclave(
    _Inout_ LPINIT_ONCE lpInitOnce, _In_ DWORD dwFlags, _Out_ PBOOL fPending, _Outptr_opt_result_maybenull_ LPVOID* lpContext);

BOOL InitOnceCompleteEnclave(_Inout_ LPINIT_ONCE lpInitOnce, _In_ DWORD dwFlags, _In_opt_ LPVOID lpContext);

#include <wil/TraceLogging.h>

#undef InitOnceBeginInitialize
#undef InitOnceComplete
#undef GetModuleHandleW
