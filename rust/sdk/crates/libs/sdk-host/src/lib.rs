// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![allow(dead_code)]
mod etw;
mod host_ffi;

pub mod common;
pub mod enclave;
pub mod userboundkey;

// Re-export AbiError for consumers who call register_sdk_callbacks
pub use sdk_host_gen::AbiError;

// Re-export HostImpl for consumers
pub use common::HostImpl;

// The userboundkey-kcm crate is not intended to be published as a standalone package.
// Long term, these KCM APIs should be consumed from the windows-rs crate.
// Until those APIs are available there, the sdk-host crate re-exports the required
// KCM surface. In practice, most consumers only need
// KeyCredentialManager::GetSecureId().
pub use userboundkey_kcm::KeyCredentialManager;

/// Register all SDK VTL0 callbacks with the enclave.
///
/// Call this function once after loading your enclave to enable SDK features.
/// This registers the necessary callbacks that allow the enclave's SDK functions
/// to communicate back to VTL0 (e.g., for Windows Hello integration).
///
/// # Arguments
///
/// * `enclave_ptr` - Pointer to the loaded enclave (from `EnclaveHandle::as_ptr()`)
///
/// # Returns
///
/// Returns `Ok(())` on success, or an error on failure.
///
/// # Example
///
/// ```rust,ignore
/// use vbsenclave_sdk_host::{register_sdk_callbacks, enclave::EnclaveHandle};
///
/// let enclave = EnclaveHandle::create_and_initialize(path, size, owner_id)?;
/// register_sdk_callbacks(enclave.as_ptr())?;
/// ```
pub fn register_sdk_callbacks(enclave_ptr: *mut core::ffi::c_void) -> Result<(), AbiError> {
    // Register SDK callbacks using the SdkHost interface and HostImpl
    let sdk_wrapper = userboundkey::SdkHost::new(enclave_ptr);
    sdk_wrapper.register_vtl0_callbacks::<HostImpl>()?;

    // Future SDK features will be added here:
    // #[cfg(feature = "secure_storage")]

    Ok(())
}
