// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// The below code is used so rust code can call into the C Apis.
#![allow(non_camel_case_types, non_snake_case, unused_imports)]

use core::ffi::c_void;
use windows::Win32::Foundation::{FARPROC, HMODULE};
use windows::core::PCSTR;

// The EdlCodeGen Core crate requires GetLastError, GetProcessHeap, HeapAlloc and HeapFree to all
// be linked manually since that crate uses them but only declares them as extern.
windows::core::link!("kernel32.dll" "system" fn GetLastError() -> u32);

windows::core::link!("kernel32.dll" "system" fn GetProcessHeap() -> *mut c_void);

windows::core::link!("kernel32.dll" "system" fn HeapAlloc(
    hheap : *mut c_void,
    dwflags : u32,
    dwbytes : usize)
-> *mut c_void);

windows::core::link!("kernel32.dll" "system" fn HeapFree(
    hheap : *mut c_void,
    dwflags : u32,
    lpmem : *const c_void)
-> i32);

// CallEnclave is not linked correctly for the host in the windows-rs crate. It is linked to
// vertdll.dll instead of kernelbase.dll, so we link it using an apiset that forwards it ourselves.
// For testing we use the mock_functions feature so calls to CallEnclave and GetProcAddress
// can be mocked for testing.
#[cfg(not(feature = "mock_functions"))]
windows::core::link!("api-ms-win-core-enclave-l1-1-1.dll" "system" fn CallEnclave(
    lproutine : isize,
    lpparameter : *const c_void,
    fwaitforthread : i32,
    lpreturnvalue : *mut *mut c_void)
-> i32);

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
