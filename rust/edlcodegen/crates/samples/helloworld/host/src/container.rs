// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use windows::core::{HRESULT, Error, Result};
use windows::Win32::Foundation::TRUE;
use crate::enclave_api_ffi::*;
use windows::Win32::System::Threading::GetCurrentProcess;
use core::ffi::c_void;

/// Temporary container for managing the lifecycle of the VBS enclave.
/// Once the Vbs enclave sdk crate is available, this can be replaced with
/// the use of lifecycle APIs from that crate.
pub struct EnclaveContainer {
    pub enclave: *mut c_void,
}

impl EnclaveContainer {
    pub fn new() -> Result<Self> {
        let mut enclave: *mut c_void = core::ptr::null_mut();
        
        let mut creation_attempt = || -> Result<()> {
            if unsafe { !IsEnclaveTypeSupported(ENCLAVE_TYPE_VBS) }.as_bool() { 
                return Err(Error::new(
                    HRESULT::from_thread(),
                    "VBS Enclaves not supported".to_string(),
                ));
            }

            // Construct ENCLAVE_CREATE_INFO_VBS with arbitrary owner ID for this sample.
            // See: https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-enclave_create_info_vbs
            let create_info: ENCLAVE_CREATE_INFO_VBS = ENCLAVE_CREATE_INFO_VBS {
                Flags: ENCLAVE_CREATE_INFO_FLAG,
                OwnerID: [
                    0x10, 0x20, 0x30, 0x40,
                    0x41, 0x31, 0x21, 0x11,
                    0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0,
                ],
            };

            let info_ptr = &raw const create_info as *const c_void;

            enclave = unsafe {
                CreateEnclave(
                    GetCurrentProcess().0,
                    core::ptr::null_mut(),
                    0x10000000,
                    0,
                    ENCLAVE_TYPE_VBS,
                    info_ptr,
                    ENCLAVE_CREATE_INFO_VBS_SIZE,
                    core::ptr::null_mut() as *mut u32,
                )
            };

            if enclave.is_null() {
                return Err(Error::new(
                    HRESULT::from_thread(),
                    "Couldn't create enclave".to_string(),
                ));
            }

            unsafe {
                if !LoadEnclaveImageW(enclave, windows::core::w!("enclave.dll")).as_bool() {
                    return Err(Error::new(
                        HRESULT::from_thread(),
                        "Couldn't load enclave".to_string(),
                    ));
                }
            }

            let mut init_info = ENCLAVE_INIT_INFO_VBS::default();
            init_info.Length = ENCLAVE_INIT_INFO_VBS_SIZE;
            init_info.ThreadCount = 1;
            
            unsafe {
                if !InitializeEnclave(
                    GetCurrentProcess().0,
                    enclave,
                    &init_info as *const _ as _,
                    init_info.Length,
                    core::ptr::null_mut() as *mut u32,
                ).as_bool() {
                    return Err(Error::new(
                        HRESULT::from_thread(),
                        "Couldn't initialize enclave".to_string(),
                    ));
                }
            }

            Ok(())
        };

        if let Err(e) = creation_attempt() {
            unsafe { Self::unload_enclave(enclave) };
            return Err(e);
        }

        Ok(Self { enclave })
    }

    unsafe fn unload_enclave(enclave: *mut c_void) {
        if !enclave.is_null() {
            unsafe {
                // Explicitly unregister ETW providers before unloading the enclave.
                let _ = vbsenclave_sdk_host::unregister_etw_providers(enclave);
                
                if !TerminateEnclave(enclave,  TRUE).as_bool() {
                    print_unload_error("Failed to terminate enclave before deletion", HRESULT::from_thread());
                    return;
                }
                
                if !DeleteEnclave(enclave).as_bool() {
                    print_unload_error("Failed to delete enclave", HRESULT::from_thread());
                }
            }
        }
    }
}

impl Drop for EnclaveContainer {
    fn drop(&mut self) {
        unsafe {
            Self::unload_enclave(self.enclave);
        }
    }
}

fn print_unload_error(err: &str, hresult: HRESULT) {
    eprintln!("{}: HRESULT 0x{:08x}", err, hresult.0);
}