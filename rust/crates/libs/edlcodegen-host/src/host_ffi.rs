// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use core::ffi::c_void;
use edlcodegen_core::{
    edl_core_ffi::AbiFuncPtr,
    edl_core_types::{AbiError, EnclaveHandle},
};

#[allow(unused_imports)]
use windows::Win32::{
    Foundation::GetLastError, Foundation::HMODULE, System::LibraryLoader::GetProcAddress,
};

pub fn get_enclave_function(
    module_param: &EnclaveHandle,
    func_name: windows::core::PCSTR,
) -> Result<AbiFuncPtr, AbiError> {
    let module = unsafe { get_proc_address(module_param.0, func_name) };

    if module.is_some() {
        let func: AbiFuncPtr = unsafe { std::mem::transmute_copy(&module) };
        Ok(func)
    } else {
        let last_err = unsafe { GetLastError() };
        Err(AbiError::Win32Error(last_err.0))
    }
}

// Used for production.
#[cfg(not(feature = "mock_functions"))]
unsafe extern "system" fn get_proc_address(
    module_param: *mut c_void,
    func_name: windows::core::PCSTR,
) -> Option<unsafe extern "system" fn() -> isize> {
    // Call into real GetProcAddress win32 function.
    return unsafe { GetProcAddress(HMODULE(module_param), func_name) };
}

// Used for testing.
#[cfg(feature = "mock_functions")]
unsafe extern "system" {
    pub fn get_proc_address(
        module_param: *mut c_void,
        func_name: windows::core::PCSTR,
    ) -> Option<unsafe extern "system" fn() -> isize>;
}
