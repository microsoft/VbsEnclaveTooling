// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! SDK implementation of the EDL Untrusted trait.
//!
//! This module provides the `HostImpl` struct that implements the generated
//! `Untrusted` trait by delegating to free functions in feature modules.
//! This pattern allows feature implementations to live in their own modules
//! while the trait impl acts as a thin wrapper.

use sdk_host_gen::AbiError;
use sdk_host_gen::implementation::types::{
    credentialAndSessionInfo, edl::WString, keyCredentialCacheConfig,
};
use sdk_host_gen::implementation::untrusted::Untrusted;

use crate::userboundkey;

/// SDK host implementation of the Untrusted trait.
///
/// This struct implements all EDL untrusted functions by delegating to
/// free functions in the appropriate feature modules.
pub struct HostImpl;

#[allow(non_snake_case)]
impl Untrusted for HostImpl {
    fn userboundkey_establish_session_for_create(
        enclave: u64,
        keyName: &WString,
        ecdhProtocol: u64,
        message: &WString,
        windowId: u64,
        cacheConfig: &keyCredentialCacheConfig,
        keyCredentialCreationOption: u32,
    ) -> Result<credentialAndSessionInfo, AbiError> {
        userboundkey::userboundkey_establish_session_for_create(
            enclave,
            keyName,
            ecdhProtocol,
            message,
            windowId,
            cacheConfig,
            keyCredentialCreationOption,
        )
    }

    fn userboundkey_establish_session_for_load(
        enclave: u64,
        keyName: &WString,
        message: &WString,
        windowId: u64,
    ) -> Result<credentialAndSessionInfo, AbiError> {
        userboundkey::userboundkey_establish_session_for_load(enclave, keyName, message, windowId)
    }

    fn userboundkey_get_authorization_context_from_credential(
        credential: u64,
        encryptedRequest: &Vec<u8>,
        message: &WString,
        windowId: u64,
    ) -> Result<Vec<u8>, AbiError> {
        userboundkey::userboundkey_get_authorization_context_from_credential(
            credential,
            encryptedRequest,
            message,
            windowId,
        )
    }

    fn userboundkey_get_secret_from_credential(
        credential: u64,
        encryptedRequest: &Vec<u8>,
        message: &WString,
        windowId: u64,
    ) -> Result<Vec<u8>, AbiError> {
        userboundkey::userboundkey_get_secret_from_credential(
            credential,
            encryptedRequest,
            message,
            windowId,
        )
    }

    fn userboundkey_format_key_name(keyName: &WString) -> Result<WString, AbiError> {
        userboundkey::userboundkey_format_key_name(keyName)
    }

    fn userboundkey_delete_credential(credential: u64) -> Result<(), AbiError> {
        userboundkey::userboundkey_delete_credential(credential)
    }
}
