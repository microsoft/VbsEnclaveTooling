// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::vertdll::*;

// The following APIs in VERTDLL.DLL should be generated but are not currently included in the Win32 metadata.

pub type PDELAYLOAD_FAILURE_SYSTEM_ROUTINE = Option<
    unsafe extern "system" fn(dllname: PCSTR, procedurename: PCSTR) -> *mut core::ffi::c_void,
>;

windows_link::link!("vertdll.dll" "system" fn EnclaveCopyIntoEnclave(enclaveaddress: *mut core::ffi::c_void, unsecureaddress: *const core::ffi::c_void, numberofbytes: usize) -> HRESULT);
windows_link::link!("vertdll.dll" "system" fn EnclaveCopyOutOfEnclave(unsecureaddress: *mut core::ffi::c_void, enclaveaddress: *const core::ffi::c_void, numberofbytes: usize) -> HRESULT);
windows_link::link!("vertdll.dll" "system" fn EnclaveRestrictContainingProcessAccess(restrictaccess: BOOL, previouslyrestricted: *mut BOOL) -> HRESULT);
windows_link::link!("vertdll.dll" "system" fn LdrDisableThreadCalloutsForDll(baseaddress: *mut core::ffi::c_void) -> NTSTATUS);
windows_link::link!("vertdll.dll" "system" fn LdrResolveDelayLoadedAPI(parentmodulebase: *const core::ffi::c_void, delayloaddescriptor: *const IMAGE_DELAYLOAD_DESCRIPTOR, failuredllhook: PDELAYLOAD_FAILURE_DLL_CALLBACK, failuresystemhook: PDELAYLOAD_FAILURE_SYSTEM_ROUTINE, thunkaddress: *mut IMAGE_THUNK_DATA32, flags: u32) -> *mut core::ffi::c_void);
windows_link::link!("vertdll.dll" "system" fn RtlGetLastNtStatus() -> NTSTATUS);
windows_link::link!("vertdll.dll" "system" fn RtlNtStatusToDosError(status: NTSTATUS) -> u32);
windows_link::link!("vertdll.dll" "system" fn RtlRaiseStatus(status: NTSTATUS));
windows_link::link!("vertdll.dll" "system" fn RtlUnhandledExceptionFilter(exceptionpointers: *const EXCEPTION_POINTERS) -> i32);

// The following are duplicated when adding them individually for VERTDLL.DLL bindings via bindgen,
// so we define them here manually.
// Created bug in windows-rs to track: https://github.com/microsoft/windows-rs/issues/3852

//HEAP_FLAGS
pub const HEAP_CREATE_ENABLE_EXECUTE: HEAP_FLAGS = 262144u32;
pub const HEAP_DISABLE_COALESCE_ON_FREE: HEAP_FLAGS = 128u32;
pub const HEAP_FREE_CHECKING_ENABLED: HEAP_FLAGS = 64u32;
pub const HEAP_GENERATE_EXCEPTIONS: HEAP_FLAGS = 4u32;
pub const HEAP_NO_SERIALIZE: HEAP_FLAGS = 1u32;
pub const HEAP_REALLOC_IN_PLACE_ONLY: HEAP_FLAGS = 16u32;
pub const HEAP_TAIL_CHECKING_ENABLED: HEAP_FLAGS = 32u32;
pub const HEAP_ZERO_MEMORY: HEAP_FLAGS = 8u32;

// VirtualAlloc / VirtualFree allocation types
pub const MEM_COMMIT: u32 = 4096u32;
pub const MEM_DECOMMIT: u32 = 16384u32;
pub const MEM_LARGE_PAGES: u32 = 536870912u32;
pub const MEM_RELEASE: u32 = 32768u32;
pub const MEM_RESERVE: u32 = 8192u32;
pub const MEM_RESET: u32 = 524288u32;
pub const MEM_RESET_UNDO: u32 = 16777216u32;

// VirtualAlloc / VirtualProtect page protections
pub const PAGE_EXECUTE: u32 = 16u32;
pub const PAGE_EXECUTE_READ: u32 = 32u32;
pub const PAGE_EXECUTE_READWRITE: u32 = 64u32;
pub const PAGE_EXECUTE_WRITECOPY: u32 = 128u32;
pub const PAGE_GUARD: u32 = 256u32;
pub const PAGE_NOACCESS: u32 = 1u32;
pub const PAGE_NOCACHE: u32 = 512u32;
pub const PAGE_READONLY: u32 = 2u32;
pub const PAGE_READWRITE: u32 = 4u32;
pub const PAGE_WRITECOMBINE: u32 = 1024u32;
pub const PAGE_WRITECOPY: u32 = 8u32;

// VirtualQuery page types
pub const MEM_IMAGE: PAGE_TYPE = 16777216u32;
pub const MEM_MAPPED: u32 = 262144u32;
pub const MEM_PRIVATE: u32 = 131072u32;

// Enclave identity constants (used for manual struct definitions if needed)
// Note: ENCLAVE_IDENTITY and ENCLAVE_INFORMATION structs are in generated bindings
pub const IMAGE_ENCLAVE_LONG_ID_LENGTH: usize = 32;
pub const IMAGE_ENCLAVE_SHORT_ID_LENGTH: usize = 16;

// Enclave type constants (not in generated bindings)
pub const ENCLAVE_TYPE_SGX: u32 = 0x00000001;
pub const ENCLAVE_TYPE_SGX2: u32 = 0x00000002;
pub const ENCLAVE_TYPE_VBS: u32 = 0x00000010;

// Enclave policy flags
#[allow(dead_code)]
pub const IMAGE_ENCLAVE_POLICY_DEBUGGABLE: u32 = 0x0000_0001;

// Enclave image flags
pub const IMAGE_ENCLAVE_FLAG_PRIMARY_IMAGE: u32 = 0x0000_0001;

/// Enclave configuration structure.
/// See: https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_enclave_config64
#[repr(C)]
pub struct ImageEnclaveConfig {
    pub size: u32,
    pub minimum_required_config_size: u32,
    pub policy_flags: u32,
    pub number_of_imports: u32,
    pub import_list: u32,
    pub import_entry_size: u32,
    pub family_id: [u8; IMAGE_ENCLAVE_SHORT_ID_LENGTH],
    pub image_id: [u8; IMAGE_ENCLAVE_SHORT_ID_LENGTH],
    pub image_version: u32,
    pub security_version: u32,
    pub enclave_size: usize,
    pub number_of_threads: u32,
    pub enclave_flags: u32,
}

/// Minimum config size required (offset of enclave_flags field).
pub const IMAGE_ENCLAVE_MINIMUM_CONFIG_SIZE: u32 =
    core::mem::offset_of!(ImageEnclaveConfig, enclave_flags) as u32;
