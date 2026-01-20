// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

mod bindings;
pub use bindings::*;

use windows_core::{HSTRING, Interface, Param};
use windows_future::IAsyncOperation;

/// Extension methods for KeyCredentialManager to access IKeyCredentialManagerStatics2 APIs.
#[allow(non_snake_case)]
impl KeyCredentialManager {
    /// Creates a key credential with VBS attestation support.
    pub fn RequestCreateAsync2(
        name: &HSTRING,
        option: KeyCredentialCreationOption,
        algorithm: &HSTRING,
        message: &HSTRING,
        cache_configuration: &KeyCredentialCacheConfiguration,
        window_id: WindowId,
        callback_type: ChallengeResponseKind,
        attestation_callback: &AttestationChallengeHandler,
    ) -> windows_core::Result<IAsyncOperation<KeyCredentialRetrievalResult>> {
        Self::IKeyCredentialManagerStatics2(|this| unsafe {
            let mut result__ = core::mem::zeroed();
            (Interface::vtable(this).RequestCreateAsync)(
                Interface::as_raw(this),
                core::mem::transmute_copy(name),
                option,
                core::mem::transmute_copy(algorithm),
                core::mem::transmute_copy(message),
                core::mem::transmute_copy(cache_configuration),
                window_id,
                callback_type,
                core::mem::transmute_copy(attestation_callback),
                &mut result__,
            )
            .and_then(|| windows_core::Type::from_abi(result__))
        })
    }

    /// Opens an existing key credential with VBS attestation support.
    pub fn OpenAsync2(
        name: &HSTRING,
        callback_type: ChallengeResponseKind,
        attestation_callback: &AttestationChallengeHandler,
    ) -> windows_core::Result<IAsyncOperation<KeyCredentialRetrievalResult>> {
        Self::IKeyCredentialManagerStatics2(|this| unsafe {
            let mut result__ = core::mem::zeroed();
            (Interface::vtable(this).OpenAsync)(
                Interface::as_raw(this),
                core::mem::transmute_copy(name),
                callback_type,
                core::mem::transmute_copy(attestation_callback),
                &mut result__,
            )
            .and_then(|| windows_core::Type::from_abi(result__))
        })
    }

    /// Gets the secure identifier for the credential manager.
    pub fn GetSecureId() -> windows_core::Result<IBuffer> {
        Self::IKeyCredentialManagerStatics2(|this| unsafe {
            let mut result__ = core::mem::zeroed();
            (Interface::vtable(this).GetSecureId)(Interface::as_raw(this), &mut result__)
                .and_then(|| windows_core::Type::from_abi(result__))
        })
    }

    fn IKeyCredentialManagerStatics2<
        R,
        F: FnOnce(&IKeyCredentialManagerStatics2) -> windows_core::Result<R>,
    >(
        callback: F,
    ) -> windows_core::Result<R> {
        static SHARED: windows_core::imp::FactoryCache<
            KeyCredentialManager,
            IKeyCredentialManagerStatics2,
        > = windows_core::imp::FactoryCache::new();
        SHARED.call(callback)
    }
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
