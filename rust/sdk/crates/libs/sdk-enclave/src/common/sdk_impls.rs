// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! SDK implementation of the EDL Trusted trait.
//!
//! This module provides the `EnclaveImpl` struct that implements the generated
//! `Trusted` trait by delegating to free functions in feature modules.
//! This pattern allows feature implementations to live in their own modules
//! while the trait impl acts as a thin wrapper.

use crate::etw;
use crate::userboundkey;
use sdk_enclave_gen::AbiError;
use sdk_enclave_gen::implementation::trusted::Trusted;
use sdk_enclave_gen::implementation::types::attestationReportAndSessionInfo;
use sdk_enclave_gen::implementation::types::{EventFilterDescriptor, Guid};

/// SDK enclave implementation of the Trusted trait.
///
/// This struct implements all EDL trusted functions by delegating to
/// free functions in the appropriate feature modules.
pub struct EnclaveImpl;

#[allow(non_snake_case)]
impl Trusted for EnclaveImpl {
    fn userboundkey_get_attestation_report(
        challenge: &[u8],
    ) -> Result<attestationReportAndSessionInfo, AbiError> {
        userboundkey::userboundkey_get_attestation_report(challenge)
    }

    fn userboundkey_close_session(sessionInfo: u64) -> Result<(), AbiError> {
        userboundkey::userboundkey_close_session(sessionInfo)
    }

    fn register_etw_providers() -> Result<(), AbiError> {
        etw::register_providers();
        Ok(())
    }

    fn unregister_etw_providers() -> Result<(), AbiError> {
        etw::unregister_providers();
        Ok(())
    }

    fn etw_callback_passthrough(
        registration_id: &Guid,
        source_id: &Guid,
        event_control_code: u32,
        level: u8,
        match_any_keyword: u64,
        match_all_keyword: u64,
        filter_data: &EventFilterDescriptor,
    ) -> Result<(), AbiError> {
        etw::etw_callback_passthrough(
            registration_id,
            source_id,
            event_control_code,
            level,
            match_any_keyword,
            match_all_keyword,
            filter_data,
        )
    }
}
