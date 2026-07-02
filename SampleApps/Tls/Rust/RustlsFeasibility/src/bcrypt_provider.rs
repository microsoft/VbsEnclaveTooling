// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;

use rustls::crypto::cipher::{
    AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, MessageDecrypter, MessageEncrypter,
    OutboundOpaqueMessage, OutboundPlainMessage, Tls13AeadAlgorithm, UnsupportedOperationError,
};
use rustls::crypto::hash::{Context as HashContext, Hash, Output as HashOutput};
use rustls::crypto::hmac::{Hmac, Key as HmacKey, Tag};
use rustls::crypto::tls13::HkdfUsingHmac;
use rustls::crypto::{
    ActiveKeyExchange, CryptoProvider, GetRandomFailed, KeyProvider, SecureRandom, SharedSecret,
    SupportedKxGroup, WebPkiSupportedAlgorithms,
};
use rustls::pki_types::PrivateKeyDer;
use rustls::sign::SigningKey;
use rustls::{
    CipherSuite, CipherSuiteCommon, ConnectionTrafficSecrets, Error, NamedGroup,
    SupportedCipherSuite, Tls13CipherSuite,
};

pub static SECURE_RANDOM: BcryptSecureRandom = BcryptSecureRandom;
pub static KEY_PROVIDER: BcryptKeyProvider = BcryptKeyProvider;
pub static SHA256: BcryptHash = BcryptHash::sha256();
pub static HMAC_SHA256: BcryptHmac = BcryptHmac::sha256();
pub static AES_256_GCM: BcryptAesGcm = BcryptAesGcm;
pub static P256: BcryptKxGroup = BcryptKxGroup::p256();
pub static P384: BcryptKxGroup = BcryptKxGroup::p384();

pub static TLS13_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&TLS13_AES_256_GCM_SHA384_INNER);

static TLS13_AES_256_GCM_SHA384_INNER: Tls13CipherSuite = Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
        hash_provider: &SHA256,
        confidentiality_limit: 1 << 24,
    },
    hkdf_provider: &HkdfUsingHmac(&HMAC_SHA256),
    aead_alg: &AES_256_GCM,
    quic: None,
};

pub static EMPTY_WEBPKI_ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[],
    mapping: &[],
};

pub fn provider_skeleton() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: Vec::from([TLS13_AES_256_GCM_SHA384]),
        kx_groups: Vec::from([
            &P256 as &'static dyn SupportedKxGroup,
            &P384 as &'static dyn SupportedKxGroup,
        ]),
        signature_verification_algorithms: EMPTY_WEBPKI_ALGORITHMS,
        secure_random: &SECURE_RANDOM,
        key_provider: &KEY_PROVIDER,
    }
}

#[derive(Debug)]
pub struct BcryptSecureRandom;

impl SecureRandom for BcryptSecureRandom {
    fn fill(&self, _buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        Err(GetRandomFailed)
    }
}

#[derive(Debug)]
pub struct BcryptKeyProvider;

impl KeyProvider for BcryptKeyProvider {
    fn load_private_key(
        &self,
        _key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn SigningKey>, Error> {
        Err(Error::General(
            "BCrypt key loading is not implemented in the feasibility skeleton".into(),
        ))
    }
}

pub struct BcryptHash {
    algorithm: rustls::crypto::hash::HashAlgorithm,
    output_len: usize,
}

impl BcryptHash {
    pub const fn sha256() -> Self {
        Self {
            algorithm: rustls::crypto::hash::HashAlgorithm::SHA256,
            output_len: 32,
        }
    }
}

impl Hash for BcryptHash {
    fn start(&self) -> Box<dyn HashContext> {
        Box::new(BcryptHashContext {
            output_len: self.output_len,
        })
    }

    fn hash(&self, _data: &[u8]) -> HashOutput {
        HashOutput::new(&[0u8; 32][..self.output_len])
    }

    fn output_len(&self) -> usize {
        self.output_len
    }

    fn algorithm(&self) -> rustls::crypto::hash::HashAlgorithm {
        self.algorithm
    }
}

pub struct BcryptHashContext {
    output_len: usize,
}

impl HashContext for BcryptHashContext {
    fn fork_finish(&self) -> HashOutput {
        HashOutput::new(&[0u8; 32][..self.output_len])
    }

    fn fork(&self) -> Box<dyn HashContext> {
        Box::new(Self {
            output_len: self.output_len,
        })
    }

    fn finish(self: Box<Self>) -> HashOutput {
        HashOutput::new(&[0u8; 32][..self.output_len])
    }

    fn update(&mut self, _data: &[u8]) {}
}

pub struct BcryptHmac {
    tag_len: usize,
}

impl BcryptHmac {
    pub const fn sha256() -> Self {
        Self { tag_len: 32 }
    }
}

impl Hmac for BcryptHmac {
    fn with_key(&self, _key: &[u8]) -> Box<dyn HmacKey> {
        Box::new(BcryptHmacKey {
            tag_len: self.tag_len,
        })
    }

    fn hash_output_len(&self) -> usize {
        self.tag_len
    }
}

pub struct BcryptHmacKey {
    tag_len: usize,
}

impl HmacKey for BcryptHmacKey {
    fn sign_concat(&self, _first: &[u8], _middle: &[&[u8]], _last: &[u8]) -> Tag {
        Tag::new(&[0u8; 64][..self.tag_len])
    }

    fn tag_len(&self) -> usize {
        self.tag_len
    }
}

pub struct BcryptAesGcm;

impl Tls13AeadAlgorithm for BcryptAesGcm {
    fn encrypter(&self, _key: AeadKey, _iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(UnsupportedEncrypter)
    }

    fn decrypter(&self, _key: AeadKey, _iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(UnsupportedDecrypter)
    }

    fn key_len(&self) -> usize {
        32
    }

    fn extract_keys(
        &self,
        _key: AeadKey,
        _iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Err(UnsupportedOperationError)
    }
}

pub struct UnsupportedEncrypter;

impl MessageEncrypter for UnsupportedEncrypter {
    fn encrypt(
        &mut self,
        _msg: OutboundPlainMessage<'_>,
        _seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        Err(Error::EncryptError)
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len
    }
}

pub struct UnsupportedDecrypter;

impl MessageDecrypter for UnsupportedDecrypter {
    fn decrypt<'a>(
        &mut self,
        _msg: InboundOpaqueMessage<'a>,
        _seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        Err(Error::DecryptError)
    }
}

#[derive(Debug)]
pub struct BcryptKxGroup {
    group: NamedGroup,
}

impl BcryptKxGroup {
    pub const fn p256() -> Self {
        Self {
            group: NamedGroup::secp256r1,
        }
    }

    pub const fn p384() -> Self {
        Self {
            group: NamedGroup::secp384r1,
        }
    }
}

impl SupportedKxGroup for BcryptKxGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        Ok(Box::new(BcryptActiveKeyExchange {
            group: self.group,
            public_key: Vec::new(),
        }))
    }

    fn name(&self) -> NamedGroup {
        self.group
    }

    fn ffdhe_group(&self) -> Option<rustls::ffdhe_groups::FfdheGroup<'static>> {
        None
    }
}

pub struct BcryptActiveKeyExchange {
    group: NamedGroup,
    public_key: Vec<u8>,
}

impl ActiveKeyExchange for BcryptActiveKeyExchange {
    fn complete(self: Box<Self>, _peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        Err(Error::General(
            "BCrypt key exchange is not implemented in the feasibility skeleton".into(),
        ))
    }

    fn pub_key(&self) -> &[u8] {
        &self.public_key
    }

    fn group(&self) -> NamedGroup {
        self.group
    }
}

impl fmt::Debug for BcryptHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BcryptHash").finish()
    }
}

impl fmt::Debug for BcryptHmac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BcryptHmac").finish()
    }
}

impl fmt::Debug for BcryptAesGcm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BcryptAesGcm").finish()
    }
}
