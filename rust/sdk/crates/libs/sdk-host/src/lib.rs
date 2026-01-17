// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

mod host_ffi;

#[cfg(feature = "userboundkey")]
pub mod userboundkey;

// The userboundkey-kcm crate is not intended to be published as a standalone package.
// Long term, these KCM APIs should be consumed from the windows-rs crate.
// Until those APIs are available there, the sdk-host crate re-exports the required
// KCM surface. In practice, most consumers only need
// KeyCredentialManager::GetSecureId().
pub use userboundkey_kcm::KeyCredentialManager;
