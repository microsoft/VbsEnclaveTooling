// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_std]
extern crate alloc;

mod enclave_ffi;

#[cfg(feature = "userboundkey")]
pub mod userboundkey;

// Re-export the userboundkey generated enclave crate.
// This is needed by applications that use the SDK's userboundkey module so they can
// export the SDK's enclave functions (callback registration, attestation, etc.).
#[cfg(feature = "userboundkey")]
pub use userboundkey_enclave_gen;
