// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows NGC (Next Generation Credentials) bindings for VBS enclave user-bound keys.
//!
//! This crate provides Rust bindings for the Windows KeyCredentialManager APIs
//! that support VBS enclave attestation. These APIs are generated using windows-bindgen.
//!
//! Key APIs:
//! - `KeyCredentialManager::RequestCreateAsync2` - Create credentials with VBS attestation
//! - `KeyCredentialManager::OpenAsync2` - Open credentials with VBS attestation
//! - `KeyCredentialManager::GetSecureId` - Get the secure identifier
//! - `KeyCredential::RequestDeriveSharedSecretAsync` - Derive shared secrets
//! - `KeyCredential::RetrieveAuthorizationContext` - Get authorization context

mod bindings;
pub use bindings::*;
