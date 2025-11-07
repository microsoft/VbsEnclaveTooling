use core::ffi::c_void;
use edlcodegen_enclave::win_enclave_bindings::ENCLAVE_INFORMATION;
use std::ptr;
use std::sync::atomic::{AtomicI32, Ordering};
use windows_result::BOOL;
use windows_sys::Win32::Foundation::{E_FAIL, ERROR_ACCESS_DENIED, S_OK, SetLastError};
use windows_sys::core::HRESULT;

type EnclaveRoutine = unsafe extern "system" fn(*mut c_void) -> *mut c_void;

#[unsafe(no_mangle)]
pub extern "C" fn CallEnclave(
    func: isize,
    param: *const c_void,
    _wait: BOOL,
    out: *mut *mut c_void,
) -> BOOL {
    if func == 0 {
        println!("[mock] CallEnclave got null func ptr");
        unsafe { SetLastError(ERROR_ACCESS_DENIED) };
        return BOOL(0);
    }

    let f: EnclaveRoutine = unsafe { core::mem::transmute(func) };
    let param_mut = param as *mut c_void;
    let result = unsafe { f(param_mut) };

    unsafe {
        *out = result;
    }

    BOOL(1)
}

#[unsafe(no_mangle)]
pub extern "C" fn EnclaveCopyIntoEnclave(dst: *mut c_void, src: *const c_void, size: usize) -> i32 {
    unsafe {
        ptr::copy_nonoverlapping(src as *const u8, dst as *mut u8, size);
    }
    println!("[mock] memcpy -> EnclaveCopyIntoEnclave ({} bytes)", size);
    S_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn EnclaveCopyOutOfEnclave(
    dst: *mut c_void,
    src: *const c_void,
    size: usize,
) -> i32 {
    unsafe {
        ptr::copy_nonoverlapping(src as *const u8, dst as *mut u8, size);
    }
    println!("[mock] memcpy -> EnclaveCopyOutOfEnclave ({} bytes)", size);
    S_OK
}

#[unsafe(no_mangle)]
pub extern "C" fn EnclaveRestrictContainingProcessAccess(_restrict: BOOL, _prev: *mut i32) -> i32 {
    static COUNT: AtomicI32 = AtomicI32::new(0);

    let count_so_far = COUNT.fetch_add(1, Ordering::SeqCst) + 1;
    println!(
        "[mock] EnclaveRestrictContainingProcessAccess invocation number: {}",
        count_so_far
    );

    if count_so_far > 1 { E_FAIL } else { S_OK }
}

#[unsafe(no_mangle)]
pub extern "system" fn EnclaveGetEnclaveInformation(
    _informationsize: u32,
    enclaveinformation: *mut ENCLAVE_INFORMATION,
) -> HRESULT {
    // SAFETY NOTE: 0x1000_0000 is a sentinel only used for address-range comparisons.
    // Do NOT dereference this pointer.
    const FAKE_BASE: usize = 0x1000_0000;
    const FAKE_SIZE: usize = 0x1_0000;

    unsafe {
        (*enclaveinformation).BaseAddress = FAKE_BASE as *mut c_void;
        (*enclaveinformation).Size = FAKE_SIZE;
    }

    S_OK
}
