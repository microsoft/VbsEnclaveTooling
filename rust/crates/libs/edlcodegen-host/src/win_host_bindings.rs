// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// The below code is used so rust code can call into the C Apis.
#![allow(non_camel_case_types, non_snake_case, unused_imports)]

use edlcodegen_core::edl_core_ffi::{HANDLE, HEAP_FLAGS, WIN32_ERROR};
use windows::Win32::Foundation::{FARPROC, HMODULE};
use windows::core::PCSTR;

// The EdlCodeGen Core crate requires GetLastError, GetProcessHeap, HeapAlloc and HeapFree to all
// be linked manually since that crate uses them but only declares them as extern.
windows::core::link!("kernel32.dll" "system" fn GetLastError() -> WIN32_ERROR);

windows::core::link!("kernel32.dll" "system" fn GetProcessHeap() -> HANDLE);

windows::core::link!("kernel32.dll" "system" fn HeapAlloc(
    hheap : HANDLE,
    dwflags : HEAP_FLAGS,
    dwbytes : usize)
-> *mut core::ffi::c_void);

windows::core::link!("kernel32.dll" "system" fn HeapFree(
    hheap : HANDLE,
    dwflags : HEAP_FLAGS,
    lpmem : *const core::ffi::c_void)
-> windows::core::BOOL);

// CallEnclave is not linked correctly for the host in the windows-rs crate. It is linked to
// vertdll.dll instead of kernel32.dll so we link it to the correct version ourselves.
// For testing we use the mock_functions feature so calls to CallEnclave and GetProcAddress
// can be mocked for testing.
#[cfg(not(feature = "mock_functions"))]
windows::core::link!("kernel32.dll" "system" fn CallEnclave(
    lproutine : isize,
    lpparameter : *const core::ffi::c_void,
    fwaitforthread : windows::core::BOOL,
    lpreturnvalue : *mut *mut core::ffi::c_void)
-> windows::core::BOOL);

#[cfg(not(feature = "mock_functions"))]
windows::core::link!("kernel32.dll" "system" fn GetProcAddress(
    hmodule : HMODULE,
    lpprocname : PCSTR
) -> FARPROC);

// Declare GetProcAddress only when `mock_functions` feature is enabled. Otherwise we use
// the real version in kernel32.dll above.
#[cfg(feature = "mock_functions")]
unsafe extern "system" {
    pub fn GetProcAddress(hmodule: HMODULE, lpprocname: PCSTR) -> FARPROC;
}
