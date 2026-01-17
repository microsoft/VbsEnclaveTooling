// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

mod bindings;
pub use bindings::*;

use windows_core::{Interface, HSTRING, Param};
use windows_future::IAsyncOperation;

// Extension constant for KeyCredentialStatus
#[allow(non_upper_case_globals)]
impl KeyCredentialStatus {
    /// Algorithm is not supported
    pub const AlgorithmNotSupported: Self = Self(7i32);
}

/// Extension methods for KeyCredential to access IKeyCredential2 APIs.
#[allow(non_snake_case)]
impl KeyCredential {
    /// Requests derivation of a shared secret using the credential.
    pub fn RequestDeriveSharedSecretAsync<P2>(
        &self,
        window_id: WindowId,
        message: &HSTRING,
        encrypted_request: P2,
    ) -> windows_core::Result<IAsyncOperation<KeyCredentialOperationResult>>
    where
        P2: Param<IBuffer>,
    {
        let this = &Interface::cast::<IKeyCredential2>(self)?;
        unsafe {
            let mut result__ = core::mem::zeroed();
            (Interface::vtable(this).RequestDeriveSharedSecretAsync)(
                Interface::as_raw(this),
                window_id,
                core::mem::transmute_copy(message),
                encrypted_request.param().abi(),
                &mut result__,
            )
            .and_then(|| windows_core::Type::from_abi(result__))
        }
    }

    /// Retrieves the authorization context for the credential.
    pub fn RetrieveAuthorizationContext<P0>(
        &self,
        encrypted_request: P0,
    ) -> windows_core::Result<IBuffer>
    where
        P0: Param<IBuffer>,
    {
        let this = &Interface::cast::<IKeyCredential2>(self)?;
        unsafe {
            let mut result__ = core::mem::zeroed();
            (Interface::vtable(this).RetrieveAuthorizationContext)(
                Interface::as_raw(this),
                encrypted_request.param().abi(),
                &mut result__,
            )
            .and_then(|| windows_core::Type::from_abi(result__))
        }
    }
}
