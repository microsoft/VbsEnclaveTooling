// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![allow(dead_code)]
mod etw;
mod host_ffi;
use veil_abi_host_gen::export_interface;

// The userboundkey-kcm crate is not intended to be published as a standalone package.
// Long term, these KCM APIs should be consumed from the windows-rs crate.
// Until those APIs are available there, the sdk-host crate re-exports the required
// KCM surface. In practice, most consumers only need
// KeyCredentialManager::GetSecureId().
pub use userboundkey_kcm::KeyCredentialManager;

/// Registers ETW providers and VTL0 callbacks for the given enclave.
pub fn register_sdk_callbacks(
    enclave: *mut core::ffi::c_void,
) -> Result<(), veil_abi_host_gen::AbiError> {
    let host = export_interface::new(enclave);

    host.register_vtl0_callbacks::<etw::HostImpl>()?;
    host.register_etw_providers()?;
    Ok(())
}

/// Unregisters ETW providers associated with the given enclave.
// TODO: This should be called during enclave teardown to unregister ETW providers.
// Once we have a enclave smart pointer. We can call this function during the drop
// implementation. For now, we will just expose this function to be called manually
// by the user of the sdk-host crate.
pub fn unregister_etw_providers(
    enclave: *mut core::ffi::c_void,
) -> Result<(), veil_abi_host_gen::AbiError> {
    let host = export_interface::new(enclave);

    host.unregister_etw_providers()?;
    Ok(())
}
