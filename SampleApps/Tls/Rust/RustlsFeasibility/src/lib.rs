// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![no_std]
extern crate alloc;

use alloc::sync::Arc;

/// Compile-only check that rustls can be referenced from a no_std + alloc crate
/// without selecting a built-in crypto provider.
pub fn make_empty_root_store() -> Arc<rustls::RootCertStore> {
    Arc::new(rustls::RootCertStore::empty())
}

/// Compile-only check that client configuration and custom provider types are
/// available without the rustls `std`, `ring`, or `aws-lc-rs` features.
pub fn provider_cipher_suite_count(provider: &rustls::crypto::CryptoProvider) -> usize {
    provider.cipher_suites.len()
}

pub fn client_config_size() -> usize {
    core::mem::size_of::<rustls::ClientConfig>()
}
