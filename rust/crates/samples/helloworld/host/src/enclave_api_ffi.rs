// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![allow(non_snake_case, non_camel_case_types)]
use core::ffi::c_void;

// Once the windows-enclave crate is available in crates.io, the windows-rs crate
// will likely have support for these APIs in their correct VTL0 dll location.
// For now, we need to manually link the required functions here since using 
// the windows::Win32::System::Environment module in the windows crate links
// TerminateEnclave from vertdll.
// See: https://github.com/microsoft/windows-rs/blob/23ec2a2267646dbb87658f1b1247eae0ec49a9e7/crates/libs/windows/src/Windows/Win32/System/Environment/mod.rs#L236C26-L236C38
windows::core::link!("api-ms-win-core-enclave-l1-1-1.dll" "system" fn TerminateEnclave(lpaddress : *const c_void, fwait : windows::core::BOOL) -> windows::core::BOOL);
windows::core::link!("api-ms-win-core-enclave-l1-1-1.dll" "system" fn DeleteEnclave(lpaddress : *const c_void) -> windows::core::BOOL);
windows::core::link!("api-ms-win-core-enclave-l1-1-1.dll" "system" fn LoadEnclaveImageW(lpenclaveaddress : *const c_void, lpimagename : windows::core::PCWSTR) -> windows::core::BOOL);
windows::core::link!("api-ms-win-core-enclave-l1-1-0.dll" "system" fn InitializeEnclave(hprocess : *mut c_void, lpaddress : *const c_void, lpenclaveinformation : *const c_void, dwinfolength : u32, lpenclaveerror : *mut u32) -> windows::core::BOOL);
windows::core::link!("api-ms-win-core-enclave-l1-1-0.dll" "system" fn IsEnclaveTypeSupported(flenclavetype : u32) -> windows::core::BOOL);
windows::core::link!("api-ms-win-core-enclave-l1-1-0.dll" "system" fn CreateEnclave(hprocess : *mut c_void , lpaddress : *const c_void, dwsize : usize, dwinitialcommitment : usize, flenclavetype : u32, lpenclaveinformation : *const c_void, dwinfolength : u32, lpenclaveerror : *mut u32) -> *mut c_void);

#[repr(C)]
#[derive(Default)]
pub struct ENCLAVE_INIT_INFO_VBS {
    pub Length: u32,
    pub ThreadCount: u32,
}

pub const ENCLAVE_INIT_INFO_VBS_SIZE: u32 = core::mem::size_of::<ENCLAVE_INIT_INFO_VBS>() as u32;

#[repr(C)]
pub struct ENCLAVE_CREATE_INFO_VBS {
    pub Flags: u32,
    pub OwnerID: [u8; 32],
}

pub const ENCLAVE_CREATE_INFO_VBS_SIZE: u32 = core::mem::size_of::<ENCLAVE_CREATE_INFO_VBS>() as u32;

pub const ENCLAVE_TYPE_VBS: u32 = 0x0000_0010;

pub const ENCLAVE_CREATE_INFO_FLAG: u32 = {
    // enable debug in debug builds
    #[cfg(debug_assertions)]
    { 0x0000_0001 }

    // disable debug in release builds
    #[cfg(not(debug_assertions))]
    { 0x0000_0000 }
};