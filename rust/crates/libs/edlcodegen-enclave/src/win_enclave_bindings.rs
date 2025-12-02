// The below code is used so rust code can call into the C Apis in vertdll. There is
// only a minimal amount of enclave specific Win32 apis needed by this crate.
#![allow(non_camel_case_types, non_snake_case, unused_imports)]
use core::ffi::c_void;

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
    pub BaseAddress: *mut c_void,
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
#[cfg(not(feature = "mock_functions"))]
windows_link::link!("vertdll.dll" "system" fn CallEnclave(
    lproutine : isize,
    lpparameter : *const c_void,
    fwaitforthread : i32,
    lpreturnvalue : *mut *mut c_void)
-> i32);

#[cfg(not(feature = "mock_functions"))]
windows_link::link!("vertdll.dll" "system" fn GetLastError() -> u32);

#[cfg(not(feature = "mock_functions"))]
windows_link::link!("vertdll.dll" "system" fn GetProcessHeap() -> *mut c_void);

#[cfg(not(feature = "mock_functions"))]
windows_link::link!("vertdll.dll" "system" fn HeapAlloc(
    hheap : *mut c_void,
    dwflags : u32,
    dwbytes : usize)
-> *mut c_void);

#[cfg(not(feature = "mock_functions"))]
windows_link::link!("vertdll.dll" "system" fn HeapFree(
    hheap : *mut c_void,
    dwflags : u32,
    lpmem : *const c_void)
-> i32);

#[cfg(not(feature = "mock_functions"))]
windows_link::link!("vertdll.dll" "system" fn EnclaveCopyIntoEnclave(
    enclaveaddress: *mut c_void,
    unsecureaddress: *const c_void,
    numberofbytes: usize)
-> i32);

#[cfg(not(feature = "mock_functions"))]
windows_link::link!("vertdll.dll" "system" fn EnclaveCopyOutOfEnclave(
    unsecureaddress: *mut c_void,
    enclaveaddress: *const c_void,
    numberofbytes: usize)
-> i32);

#[cfg(not(feature = "mock_functions"))]
windows_link::link!("vertdll.dll" "system" fn EnclaveRestrictContainingProcessAccess(
    restrictaccess: i32,
    previouslyrestricted: *mut i32)
-> i32);

#[cfg(not(feature = "mock_functions"))]
windows_link::link!("vertdll.dll" "system" fn EnclaveGetEnclaveInformation(
    informationsize : u32,
    enclaveinformation : *mut ENCLAVE_INFORMATION)
-> i32);

// Mocked in tests so we only need to declare and not implement them here.
#[cfg(feature = "mock_functions")]
unsafe extern "system" {
    pub fn EnclaveCopyIntoEnclave(
        enclaveaddress: *mut c_void,
        unsecureaddress: *const c_void,
        numberofbytes: usize,
    ) -> i32;

    pub fn EnclaveCopyOutOfEnclave(
        unsecureaddress: *mut c_void,
        enclaveaddress: *const c_void,
        numberofbytes: usize,
    ) -> i32;

    pub fn EnclaveRestrictContainingProcessAccess(
        restrictaccess: i32,
        previouslyrestricted: *mut i32,
    ) -> i32;

    pub fn EnclaveGetEnclaveInformation(
        informationsize: u32,
        enclaveinformation: *mut ENCLAVE_INFORMATION,
    ) -> i32;
}
