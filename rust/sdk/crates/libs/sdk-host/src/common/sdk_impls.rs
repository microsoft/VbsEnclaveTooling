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
    EventDataDescriptor, EventDescriptor, Guid, credentialAndSessionInfo, edl::WString,
    keyCredentialCacheConfig,
};
use sdk_host_gen::implementation::untrusted::Untrusted;

use crate::etw;
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
        keyName: &U16Str,
        ecdhProtocol: u64,
        message: &U16Str,
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
        keyName: &U16Str,
        message: &U16Str,
        windowId: u64,
    ) -> Result<credentialAndSessionInfo, AbiError> {
        userboundkey::userboundkey_establish_session_for_load(enclave, keyName, message, windowId)
    }

    fn userboundkey_get_authorization_context_from_credential(
        credential: u64,
        encryptedRequest: &[u8],
        message: &U16Str,
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
        encryptedRequest: &[u8],
        message: &U16Str,
        windowId: u64,
    ) -> Result<Vec<u8>, AbiError> {
        userboundkey::userboundkey_get_secret_from_credential(
            credential,
            encryptedRequest,
            message,
            windowId,
        )
    }

    fn userboundkey_format_key_name(keyName: &U16Str) -> Result<U16String, AbiError> {
        userboundkey::userboundkey_format_key_name(keyName)
    }

    fn userboundkey_delete_credential(credential: u64) -> Result<(), AbiError> {
        userboundkey::userboundkey_delete_credential(credential)
    }

    fn event_unregister(reg_handle: u64) -> Result<u32, AbiError> {
        etw::event_unregister(reg_handle)
    }

    fn event_register(
        provider_id: &Guid,
        registration_id: &Guid,
        enclave: u64,
        reg_handle: &mut u64,
    ) -> Result<u32, AbiError> {
        etw::event_register(provider_id, registration_id, enclave, reg_handle)
    }

    fn event_write_transfer(
        reg_handle: u64,
        descriptor: &EventDescriptor,
        activity_id: &Option<Guid>,
        related_id: &Option<Guid>,
        user_data: &Vec<EventDataDescriptor>,
    ) -> Result<u32, AbiError> {
        etw::event_write_transfer(reg_handle, descriptor, activity_id, related_id, user_data)
    }

    fn event_set_information(
        reg_handle: u64,
        information_class: u32,
        information: &Vec<u8>,
    ) -> Result<u32, AbiError> {
        etw::event_set_information(reg_handle, information_class, information)
    }

    fn event_activity_id_control(
        control_code: u32,
        activity_id: &mut Guid,
    ) -> Result<u32, AbiError> {
        etw::event_activity_id_control(control_code, activity_id)
    }

    fn println(msg: &String) -> Result<(), AbiError> {
        super::enclave_println(msg);
        Ok(())
    }
}
