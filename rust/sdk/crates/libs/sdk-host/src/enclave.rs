// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! VBS Enclave lifecycle management APIs.
//!
//! This module provides APIs for creating, loading, initializing, and
//! cleaning up VBS enclaves.
//!
//! # Example
//!
//! ```no_run
//! use vbsenclave_sdk_host::enclave::{EnclaveHandle, megabytes};
//! use std::path::Path;
//!
//! // Create and initialize an enclave
//! let enclave = EnclaveHandle::create_and_initialize(
//!     Path::new("my_enclave.dll"),
//!     megabytes(32),
//!     None, // Use default owner ID
//! )?;
//!
//! // Use enclave.as_ptr() for enclave calls
//! // Enclave is automatically terminated and deleted when dropped
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use std::ffi::c_void;
use std::path::Path;
use windows::core::{Error, HRESULT, Result};

// FFI declarations for enclave APIs
mod ffi {
    use std::ffi::c_void;

    windows::core::link!("api-ms-win-core-enclave-l1-1-0.dll" "system" fn CreateEnclave(
        hprocess: *mut c_void,
        lpaddress: *const c_void,
        dwsize: usize,
        dwinitialcommitment: usize,
        flenclavetype: u32,
        lpenclaveinformation: *const c_void,
        dwinfolength: u32,
        lpenclaveerror: *mut u32
    ) -> *mut c_void);

    windows::core::link!("api-ms-win-core-enclave-l1-1-0.dll" "system" fn LoadEnclaveImageW(
        lpenclaveaddress: *const c_void,
        lpimagename: *const u16
    ) -> i32);

    windows::core::link!("api-ms-win-core-enclave-l1-1-0.dll" "system" fn InitializeEnclave(
        hprocess: *mut c_void,
        lpaddress: *const c_void,
        lpenclaveinformation: *const c_void,
        dwinfolength: u32,
        lpenclaveerror: *mut u32
    ) -> i32);

    windows::core::link!("api-ms-win-core-enclave-l1-1-0.dll" "system" fn TerminateEnclave(
        lpaddress: *const c_void,
        fwait: i32
    ) -> i32);

    windows::core::link!("api-ms-win-core-enclave-l1-1-0.dll" "system" fn DeleteEnclave(
        lpaddress: *const c_void
    ) -> i32);

    windows::core::link!("api-ms-win-core-enclave-l1-1-0.dll" "system" fn IsEnclaveTypeSupported(
        flenclavetype: u32
    ) -> i32);
}

/// VBS enclave type constant.
pub const ENCLAVE_TYPE_VBS: u32 = 0x10;

/// Length of the enclave owner ID.
pub const IMAGE_ENCLAVE_LONG_ID_LENGTH: usize = 32;

/// Default enclave size (32 MB).
pub const DEFAULT_ENCLAVE_SIZE: usize = 32 * 1024 * 1024;

/// Enclave creation info for VBS enclaves.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EnclaveCreateInfoVbs {
    /// Flags for enclave creation.
    pub flags: u32,
    /// Owner ID for the enclave.
    pub owner_id: [u8; IMAGE_ENCLAVE_LONG_ID_LENGTH],
}

impl Default for EnclaveCreateInfoVbs {
    fn default() -> Self {
        Self {
            flags: 0,
            owner_id: [0u8; IMAGE_ENCLAVE_LONG_ID_LENGTH],
        }
    }
}

/// Enclave initialization info for VBS enclaves.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EnclaveInitInfoVbs {
    /// Size of this structure.
    pub length: u32,
    /// Number of threads to create.
    pub thread_count: u32,
}

impl Default for EnclaveInitInfoVbs {
    fn default() -> Self {
        Self {
            length: core::mem::size_of::<Self>() as u32,
            thread_count: 1,
        }
    }
}

/// Convert megabytes to bytes.
#[inline]
pub const fn megabytes(mb: usize) -> usize {
    mb * 0x100000
}

/// Check if VBS enclaves are supported on this system.
pub fn is_vbs_supported() -> bool {
    unsafe { ffi::IsEnclaveTypeSupported(ENCLAVE_TYPE_VBS) != 0 }
}

/// Create a new VBS enclave.
///
/// # Arguments
///
/// * `size` - Size of the enclave in bytes. Use [`megabytes`] helper.
/// * `owner_id` - Optional owner ID. If None, uses zeros.
/// * `flags` - Enclave creation flags.
/// * `initial_commitment` - Initial memory commitment (usually 0).
///
/// # Returns
///
/// Raw pointer to the enclave on success.
///
/// # Errors
///
/// Returns an error if VBS is not supported or enclave creation fails.
pub fn create(
    size: usize,
    owner_id: Option<&[u8]>,
    flags: u32,
    initial_commitment: usize,
) -> Result<*mut c_void> {
    if !is_vbs_supported() {
        return Err(Error::new(
            HRESULT(-2147024891i32), // E_ACCESSDENIED
            "VBS enclave type not supported",
        ));
    }

    let mut create_info = EnclaveCreateInfoVbs {
        flags,
        owner_id: [0u8; IMAGE_ENCLAVE_LONG_ID_LENGTH],
    };

    if let Some(id) = owner_id {
        let len = id.len().min(IMAGE_ENCLAVE_LONG_ID_LENGTH);
        create_info.owner_id[..len].copy_from_slice(&id[..len]);
    }

    let mut enclave_error: u32 = 0;

    let enclave = unsafe {
        ffi::CreateEnclave(
            -1isize as *mut c_void, // GetCurrentProcess() pseudo-handle
            std::ptr::null(),       // Let system choose address
            size,
            initial_commitment,
            ENCLAVE_TYPE_VBS,
            &create_info as *const _ as *const c_void,
            core::mem::size_of::<EnclaveCreateInfoVbs>() as u32,
            &mut enclave_error,
        )
    };

    if enclave.is_null() {
        let last_error = unsafe { windows::Win32::Foundation::GetLastError() };
        return Err(Error::new(
            HRESULT::from_win32(last_error.0),
            "Failed to create VBS enclave",
        ));
    }

    Ok(enclave)
}

/// Load an enclave image (DLL) into an existing enclave.
///
/// # Arguments
///
/// * `enclave` - Pointer to the enclave.
/// * `image_path` - Path to the enclave DLL.
///
/// # Errors
///
/// Returns an error if loading fails.
pub fn load_image(enclave: *mut c_void, image_path: &Path) -> Result<()> {
    let wide_path: Vec<u16> = image_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let result = unsafe { ffi::LoadEnclaveImageW(enclave, wide_path.as_ptr()) };

    if result == 0 {
        let last_error = unsafe { windows::Win32::Foundation::GetLastError() };
        return Err(Error::new(
            HRESULT::from_win32(last_error.0),
            "Failed to load enclave image",
        ));
    }

    Ok(())
}

use std::os::windows::ffi::OsStrExt;

/// Initialize an enclave after loading its image.
///
/// # Arguments
///
/// * `enclave` - Pointer to the enclave.
/// * `thread_count` - Number of threads to create (usually 1).
///
/// # Errors
///
/// Returns an error if initialization fails.
pub fn initialize(enclave: *mut c_void, thread_count: u32) -> Result<()> {
    let init_info = EnclaveInitInfoVbs {
        length: core::mem::size_of::<EnclaveInitInfoVbs>() as u32,
        thread_count,
    };

    let mut enclave_error: u32 = 0;

    let result = unsafe {
        ffi::InitializeEnclave(
            -1isize as *mut c_void, // GetCurrentProcess()
            enclave,
            &init_info as *const _ as *const c_void,
            init_info.length,
            &mut enclave_error,
        )
    };

    if result == 0 {
        let last_error = unsafe { windows::Win32::Foundation::GetLastError() };
        return Err(Error::new(
            HRESULT::from_win32(last_error.0),
            "Failed to initialize enclave",
        ));
    }

    Ok(())
}

/// Terminate an enclave.
///
/// # Arguments
///
/// * `enclave` - Pointer to the enclave.
/// * `wait` - If true, wait for all threads to terminate.
pub fn terminate(enclave: *mut c_void, wait: bool) {
    unsafe {
        let _ = ffi::TerminateEnclave(enclave, if wait { 1 } else { 0 });
    }
}

/// Delete an enclave.
///
/// # Arguments
///
/// * `enclave` - Pointer to the enclave.
pub fn delete(enclave: *mut c_void) {
    unsafe {
        let _ = ffi::DeleteEnclave(enclave);
    }
}

/// A handle to a VBS enclave that manages its lifecycle.
///
/// When dropped, the enclave is automatically terminated and deleted.
pub struct EnclaveHandle {
    enclave: *mut c_void,
}

impl EnclaveHandle {
    /// Create a new enclave handle from a raw pointer.
    ///
    /// # Safety
    ///
    /// The caller must ensure the pointer is a valid enclave pointer
    /// that was created with `CreateEnclave`.
    pub unsafe fn from_raw(enclave: *mut c_void) -> Self {
        Self { enclave }
    }

    /// Create, load, and initialize a VBS enclave in one step.
    ///
    /// This is the recommended way to create an enclave. It:
    /// 1. Creates the enclave
    /// 2. Loads the enclave DLL
    /// 3. Initializes the enclave with 2 threads (needed for callback support)
    ///
    /// # Arguments
    ///
    /// * `dll_path` - Path to the enclave DLL.
    /// * `size` - Size of the enclave in bytes. Use [`megabytes`] helper.
    /// * `owner_id` - Optional owner ID bytes. If None, uses zeros.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use vbsenclave_sdk_host::enclave::{EnclaveHandle, megabytes};
    /// use std::path::Path;
    ///
    /// let enclave = EnclaveHandle::create_and_initialize(
    ///     Path::new("my_enclave.dll"),
    ///     megabytes(32),
    ///     None,
    /// )?;
    /// # Ok::<(), windows::core::Error>(())
    /// ```
    pub fn create_and_initialize(
        dll_path: &Path,
        size: usize,
        owner_id: Option<&[u8]>,
    ) -> Result<Self> {
        // Default to 2 threads for callback support (e.g., Windows Hello attestation)
        Self::create_and_initialize_with_threads(dll_path, size, owner_id, 2)
    }

    /// Create, load, and initialize a VBS enclave with a specific thread count.
    ///
    /// Use this when you need more control over the number of enclave threads.
    /// For user-bound key operations, at least 2 threads are required.
    ///
    /// # Arguments
    ///
    /// * `dll_path` - Path to the enclave DLL.
    /// * `size` - Size of the enclave in bytes. Use [`megabytes`] helper.
    /// * `owner_id` - Optional owner ID bytes. If None, uses zeros.
    /// * `thread_count` - Number of threads to initialize. Use at least 2 for callback support.
    pub fn create_and_initialize_with_threads(
        dll_path: &Path,
        size: usize,
        owner_id: Option<&[u8]>,
        thread_count: u32,
    ) -> Result<Self> {
        // Create the enclave
        let enclave_ptr = create(size, owner_id, 0, 0)?;

        // If any subsequent step fails, we need to clean up
        let handle = unsafe { Self::from_raw(enclave_ptr) };

        // Load the enclave image
        load_image(enclave_ptr, dll_path)?;

        // Initialize with specified thread count
        initialize(enclave_ptr, thread_count)?;

        Ok(handle)
    }

    /// Get the raw enclave pointer for use with enclave calls.
    #[inline]
    pub fn as_ptr(&self) -> *mut c_void {
        self.enclave
    }

    /// Consume this handle without running the destructor.
    ///
    /// The caller becomes responsible for terminating and deleting the enclave.
    pub fn into_raw(self) -> *mut c_void {
        let ptr = self.enclave;
        std::mem::forget(self);
        ptr
    }
}

impl Drop for EnclaveHandle {
    fn drop(&mut self) {
        if !self.enclave.is_null() {
            // fWait = TRUE means wait for all threads to terminate
            terminate(self.enclave, true);
            delete(self.enclave);
        }
    }
}

// EnclaveHandle is Send but not Sync - you can move it between threads
// but shouldn't share references across threads.
unsafe impl Send for EnclaveHandle {}
