// The below code is used so rust code can call into the C Apis in vertdll. There is
// only a minimal amount of enclave specific Win32 apis needed by this crate.
#![allow(non_camel_case_types, non_snake_case, unused_imports)]
use edlcodegen_core::edl_core_ffi::{HANDLE, HEAP_FLAGS, HEAP_ZERO_MEMORY, WIN32_ERROR};
use windows_sys::core::{BOOL, HRESULT};

#[repr(C, packed(1))]
#[derive(Clone, Copy)]
pub struct ENCLAVE_IDENTITY {
    pub OwnerId: [u8; 32],
    pub UniqueId: [u8; 32],
    pub AuthorId: [u8; 32],
    pub FamilyId: [u8; 16],
    pub ImageId: [u8; 16],
    pub EnclaveSvn: u32,
    pub SecureKernelSvn: u32,
    pub PlatformSvn: u32,
    pub Flags: u32,
    pub SigningLevel: u32,
    pub EnclaveType: u32,
}

impl Default for ENCLAVE_IDENTITY {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ENCLAVE_INFORMATION {
    pub EnclaveType: u32,
    pub Reserved: u32,
    pub BaseAddress: *mut core::ffi::c_void,
    pub Size: usize,
    pub Identity: ENCLAVE_IDENTITY,
}

impl Default for ENCLAVE_INFORMATION {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

// Only use and link the following functions directly from vertdll.dll when the
// feature "mock_functions" is not enabled.
#[cfg(not(any(test, feature = "mock_functions")))]
windows_link::link!("vertdll.dll" "system" fn CallEnclave(
    lproutine : isize,
    lpparameter : *const core::ffi::c_void,
    fwaitforthread : BOOL,
    lpreturnvalue : *mut *mut core::ffi::c_void)
-> BOOL);

#[cfg(not(any(test, feature = "mock_functions")))]
windows_link::link!("vertdll.dll" "system" fn GetLastError() -> WIN32_ERROR);

#[cfg(not(any(test, feature = "mock_functions")))]
windows_link::link!("vertdll.dll" "system" fn GetProcessHeap() -> HANDLE);

#[cfg(not(any(test, feature = "mock_functions")))]
windows_link::link!("vertdll.dll" "system" fn HeapAlloc(
    hheap : HANDLE,
    dwflags : HEAP_FLAGS,
    dwbytes : usize)
-> *mut core::ffi::c_void);

#[cfg(not(any(test, feature = "mock_functions")))]
windows_link::link!("vertdll.dll" "system" fn HeapFree(
    hheap : HANDLE,
    dwflags : HEAP_FLAGS,
    lpmem : *const core::ffi::c_void)
-> BOOL);

#[cfg(not(any(test, feature = "mock_functions")))]
windows_link::link!("vertdll.dll" "system" fn EnclaveCopyIntoEnclave(
    enclaveaddress: *mut core::ffi::c_void,
    unsecureaddress: *const core::ffi::c_void,
    numberofbytes: usize)
-> HRESULT);

#[cfg(not(any(test, feature = "mock_functions")))]
windows_link::link!("vertdll.dll" "system" fn EnclaveCopyOutOfEnclave(
    unsecureaddress: *mut core::ffi::c_void,
    enclaveaddress: *const core::ffi::c_void,
    numberofbytes: usize)
-> HRESULT);

#[cfg(not(any(test, feature = "mock_functions")))]
windows_link::link!("vertdll.dll" "system" fn EnclaveRestrictContainingProcessAccess(
    restrictaccess: BOOL,
    previouslyrestricted: *mut BOOL)
-> HRESULT);

#[cfg(not(any(test, feature = "mock_functions")))]
windows_link::link!("vertdll.dll" "system" fn EnclaveGetEnclaveInformation(
    informationsize : u32,
    enclaveinformation : *mut ENCLAVE_INFORMATION)
-> HRESULT);

// Mocked in tests so we only need to declare and not implement them here.
#[cfg(any(test, feature = "mock_functions"))]
unsafe extern "system" {
    pub fn EnclaveCopyIntoEnclave(
        enclaveaddress: *mut core::ffi::c_void,
        unsecureaddress: *const core::ffi::c_void,
        numberofbytes: usize,
    ) -> HRESULT;

    pub fn EnclaveCopyOutOfEnclave(
        unsecureaddress: *mut core::ffi::c_void,
        enclaveaddress: *const core::ffi::c_void,
        numberofbytes: usize,
    ) -> HRESULT;

    pub fn EnclaveRestrictContainingProcessAccess(
        restrictaccess: BOOL,
        previouslyrestricted: *mut BOOL,
    ) -> HRESULT;

    pub fn EnclaveGetEnclaveInformation(
        informationsize: u32,
        enclaveinformation: *mut ENCLAVE_INFORMATION,
    ) -> HRESULT;
}
