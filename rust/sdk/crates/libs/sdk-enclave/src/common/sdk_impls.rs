// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! SDK implementation of the EDL Trusted trait.
//!
//! This module provides the `EnclaveImpl` struct that implements the generated
//! `Trusted` trait by delegating to free functions in feature modules.
//! This pattern allows feature implementations to live in their own modules
//! while the trait impl acts as a thin wrapper.

use sdk_enclave_gen::AbiError;
use sdk_enclave_gen::implementation::trusted::Trusted;
use sdk_enclave_gen::implementation::types::attestationReportAndSessionInfo;

use crate::userboundkey;

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
}
