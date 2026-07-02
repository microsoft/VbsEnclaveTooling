// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use rustls::crypto::cipher::{
    make_tls13_aad, AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, MessageDecrypter,
    MessageEncrypter, Nonce, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload,
    Tls13AeadAlgorithm, UnsupportedOperationError,
};
use rustls::crypto::hash::{Context as HashContext, Hash, Output as HashOutput};
use rustls::crypto::hmac::{Hmac, Key as HmacKey, Tag};
use rustls::crypto::tls13::HkdfUsingHmac;
use rustls::crypto::{
    ActiveKeyExchange, CryptoProvider, GetRandomFailed, KeyProvider, SecureRandom, SharedSecret,
    SupportedKxGroup, WebPkiSupportedAlgorithms,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::sign::SigningKey;
use rustls::{
    CipherSuite, CipherSuiteCommon, ConnectionTrafficSecrets, ContentType, DigitallySignedStruct,
    Error, NamedGroup, ProtocolVersion, SignatureScheme,
    SupportedCipherSuite, Tls13CipherSuite,
};
use windows_enclave::bcrypt::{
    BCryptCreateHash, BCryptDeriveKey, BCryptDestroyHash, BCryptDestroyKey, BCryptDestroySecret,
    BCryptDecrypt, BCryptEncrypt, BCryptExportKey, BCryptFinalizeKeyPair, BCryptFinishHash,
    BCryptGenRandom, BCryptGenerateKeyPair, BCryptGenerateSymmetricKey, BCryptHash,
    BCryptHashData, BCryptImportKeyPair, BCryptSecretAgreement, BCryptVerifySignature,
    BCRYPT_AES_GCM_ALG_HANDLE, BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO,
    BCRYPT_ECDH_P256_ALG_HANDLE, BCRYPT_ECDH_P384_ALG_HANDLE, BCRYPT_HASH_HANDLE,
    BCRYPT_HMAC_SHA384_ALG_HANDLE,
    BCRYPT_HMAC_SHA256_ALG_HANDLE, BCRYPT_KEY_HANDLE, BCRYPT_SECRET_HANDLE,
    BCRYPT_PAD_PKCS1, BCRYPT_PAD_PSS, BCRYPT_RSA_ALG_HANDLE, BCRYPT_SHA256_ALG_HANDLE,
    BCRYPT_SHA384_ALG_HANDLE,
    BCRYPT_USE_SYSTEM_PREFERRED_RNG,
};

pub static SECURE_RANDOM: BcryptSecureRandom = BcryptSecureRandom;
pub static KEY_PROVIDER: BcryptKeyProvider = BcryptKeyProvider;
pub static SHA256: BcryptHash = BcryptHash::sha256();
pub static SHA384: BcryptHash = BcryptHash::sha384();
pub static HMAC_SHA256: BcryptHmac = BcryptHmac::sha256();
pub static HMAC_SHA384: BcryptHmac = BcryptHmac::sha384();
pub static AES_256_GCM: BcryptAesGcm = BcryptAesGcm;
pub static P256: BcryptKxGroup = BcryptKxGroup::p256();
pub static P384: BcryptKxGroup = BcryptKxGroup::p384();

const BCRYPT_ECDH_PUBLIC_P256_MAGIC: u32 = 0x314b_4345;
const BCRYPT_ECDH_PUBLIC_P384_MAGIC: u32 = 0x334b_4345;
const BCRYPT_ECCPUBLIC_BLOB: [u16; 14] = [
    b'E' as u16,
    b'C' as u16,
    b'C' as u16,
    b'P' as u16,
    b'U' as u16,
    b'B' as u16,
    b'L' as u16,
    b'I' as u16,
    b'C' as u16,
    b'B' as u16,
    b'L' as u16,
    b'O' as u16,
    b'B' as u16,
    0,
];
const BCRYPT_KDF_RAW_SECRET: [u16; 9] = [
    b'T' as u16,
    b'R' as u16,
    b'U' as u16,
    b'N' as u16,
    b'C' as u16,
    b'A' as u16,
    b'T' as u16,
    b'E' as u16,
    0,
];
const BCRYPT_RSAPUBLIC_MAGIC: u32 = 0x3141_5352;
const BCRYPT_RSAPUBLIC_BLOB: [u16; 14] = [
    b'R' as u16,
    b'S' as u16,
    b'A' as u16,
    b'P' as u16,
    b'U' as u16,
    b'B' as u16,
    b'L' as u16,
    b'I' as u16,
    b'C' as u16,
    b'B' as u16,
    b'L' as u16,
    b'O' as u16,
    b'B' as u16,
    0,
];
const BCRYPT_SHA256_ALGORITHM: [u16; 7] = [
    b'S' as u16,
    b'H' as u16,
    b'A' as u16,
    b'2' as u16,
    b'5' as u16,
    b'6' as u16,
    0,
];

#[repr(C)]
struct BcryptPkcs1PaddingInfo {
    psz_alg_id: *const u16,
}

#[repr(C)]
struct BcryptPssPaddingInfo {
    psz_alg_id: *const u16,
    cb_salt: u32,
}

pub static TLS13_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&TLS13_AES_256_GCM_SHA384_INNER);

static TLS13_AES_256_GCM_SHA384_INNER: Tls13CipherSuite = Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
        hash_provider: &SHA384,
        confidentiality_limit: 1 << 24,
    },
    hkdf_provider: &HkdfUsingHmac(&HMAC_SHA384),
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
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        let status = unsafe {
            BCryptGenRandom(
                core::ptr::null_mut(),
                buf.as_mut_ptr(),
                buf.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if status < 0 {
            Err(GetRandomFailed)
        } else {
            Ok(())
        }
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
    bcrypt_algorithm: BcryptAlgorithm,
    output_len: usize,
}

#[derive(Clone, Copy, Debug)]
enum BcryptAlgorithm {
    Sha256,
    Sha384,
    HmacSha256,
    HmacSha384,
    EcdhP256,
    EcdhP384,
}

impl BcryptAlgorithm {
    fn handle(self) -> BCRYPT_KEY_HANDLE {
        match self {
            Self::Sha256 => BCRYPT_SHA256_ALG_HANDLE,
            Self::Sha384 => BCRYPT_SHA384_ALG_HANDLE,
            Self::HmacSha256 => BCRYPT_HMAC_SHA256_ALG_HANDLE,
            Self::HmacSha384 => BCRYPT_HMAC_SHA384_ALG_HANDLE,
            Self::EcdhP256 => BCRYPT_ECDH_P256_ALG_HANDLE,
            Self::EcdhP384 => BCRYPT_ECDH_P384_ALG_HANDLE,
        }
    }
}

impl BcryptHash {
    pub const fn sha256() -> Self {
        Self {
            algorithm: rustls::crypto::hash::HashAlgorithm::SHA256,
            bcrypt_algorithm: BcryptAlgorithm::Sha256,
            output_len: 32,
        }
    }

    pub const fn sha384() -> Self {
        Self {
            algorithm: rustls::crypto::hash::HashAlgorithm::SHA384,
            bcrypt_algorithm: BcryptAlgorithm::Sha384,
            output_len: 48,
        }
    }
}

impl Hash for BcryptHash {
    fn start(&self) -> Box<dyn HashContext> {
        Box::new(BcryptHashContext {
            bcrypt_algorithm: self.bcrypt_algorithm,
            output_len: self.output_len,
            data: Vec::new(),
        })
    }

    fn hash(&self, data: &[u8]) -> HashOutput {
        let mut output = [0u8; 64];
        let status = unsafe {
            BCryptHash(
                self.bcrypt_algorithm.handle(),
                core::ptr::null(),
                0,
                data.as_ptr(),
                data.len() as u32,
                output.as_mut_ptr(),
                self.output_len as u32,
            )
        };
        if status < 0 {
            return HashOutput::new(&[]);
        }
        HashOutput::new(&output[..self.output_len])
    }

    fn output_len(&self) -> usize {
        self.output_len
    }

    fn algorithm(&self) -> rustls::crypto::hash::HashAlgorithm {
        self.algorithm
    }
}

pub struct BcryptHashContext {
    bcrypt_algorithm: BcryptAlgorithm,
    output_len: usize,
    data: Vec<u8>,
}

impl HashContext for BcryptHashContext {
    fn fork_finish(&self) -> HashOutput {
        BcryptHash {
            algorithm: rustls::crypto::hash::HashAlgorithm::SHA384,
            bcrypt_algorithm: self.bcrypt_algorithm,
            output_len: self.output_len,
        }
        .hash(&self.data)
    }

    fn fork(&self) -> Box<dyn HashContext> {
        Box::new(Self {
            bcrypt_algorithm: self.bcrypt_algorithm,
            output_len: self.output_len,
            data: self.data.clone(),
        })
    }

    fn finish(self: Box<Self>) -> HashOutput {
        self.fork_finish()
    }

    fn update(&mut self, data: &[u8]) {
        self.data.extend_from_slice(data);
    }
}

pub struct BcryptHmac {
    bcrypt_algorithm: BcryptAlgorithm,
    tag_len: usize,
}

impl BcryptHmac {
    pub const fn sha256() -> Self {
        Self {
            bcrypt_algorithm: BcryptAlgorithm::HmacSha256,
            tag_len: 32,
        }
    }

    pub const fn sha384() -> Self {
        Self {
            bcrypt_algorithm: BcryptAlgorithm::HmacSha384,
            tag_len: 48,
        }
    }
}

impl Hmac for BcryptHmac {
    fn with_key(&self, key: &[u8]) -> Box<dyn HmacKey> {
        Box::new(BcryptHmacKey {
            bcrypt_algorithm: self.bcrypt_algorithm,
            key: key.to_vec(),
            tag_len: self.tag_len,
        })
    }

    fn hash_output_len(&self) -> usize {
        self.tag_len
    }
}

pub struct BcryptHmacKey {
    bcrypt_algorithm: BcryptAlgorithm,
    key: Vec<u8>,
    tag_len: usize,
}

impl HmacKey for BcryptHmacKey {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> Tag {
        let mut hash: BCRYPT_HASH_HANDLE = core::ptr::null_mut();
        let mut output = [0u8; 64];
        let create_status = unsafe {
            BCryptCreateHash(
                self.bcrypt_algorithm.handle(),
                &mut hash,
                core::ptr::null_mut(),
                0,
                self.key.as_ptr(),
                self.key.len() as u32,
                0,
            )
        };
        if create_status < 0 {
            return Tag::new(&[]);
        }

        let mut status = unsafe { BCryptHashData(hash, first.as_ptr(), first.len() as u32, 0) };
        for part in middle {
            if status >= 0 {
                status = unsafe { BCryptHashData(hash, part.as_ptr(), part.len() as u32, 0) };
            }
        }
        if status >= 0 {
            status = unsafe { BCryptHashData(hash, last.as_ptr(), last.len() as u32, 0) };
        }
        if status >= 0 {
            status = unsafe {
                BCryptFinishHash(hash, output.as_mut_ptr(), self.tag_len as u32, 0)
            };
        }
        unsafe {
            BCryptDestroyHash(hash);
        }
        if status < 0 {
            return Tag::new(&[]);
        }
        Tag::new(&output[..self.tag_len])
    }

    fn tag_len(&self) -> usize {
        self.tag_len
    }
}

pub struct BcryptAesGcm;

impl Tls13AeadAlgorithm for BcryptAesGcm {
    fn encrypter(&self, _key: AeadKey, _iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(BcryptAesGcmEncrypter::new(_key, _iv))
    }

    fn decrypter(&self, _key: AeadKey, _iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(BcryptAesGcmDecrypter::new(_key, _iv))
    }

    fn key_len(&self) -> usize {
        32
    }

    fn extract_keys(
        &self,
        _key: AeadKey,
        _iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Aes256Gcm { key: _key, iv: _iv })
    }
}

struct BcryptAesGcmKey(BCRYPT_KEY_HANDLE);

unsafe impl Send for BcryptAesGcmKey {}
unsafe impl Sync for BcryptAesGcmKey {}

impl BcryptAesGcmKey {
    fn new(key: AeadKey) -> Option<Self> {
        let mut handle: BCRYPT_KEY_HANDLE = core::ptr::null_mut();
        let status = unsafe {
            BCryptGenerateSymmetricKey(
                BCRYPT_AES_GCM_ALG_HANDLE,
                &mut handle,
                core::ptr::null_mut(),
                0,
                key.as_ref().as_ptr(),
                key.as_ref().len() as u32,
                0,
            )
        };
        if status < 0 {
            None
        } else {
            Some(Self(handle))
        }
    }
}

impl Drop for BcryptAesGcmKey {
    fn drop(&mut self) {
        unsafe {
            BCryptDestroyKey(self.0);
        }
    }
}

pub struct BcryptAesGcmEncrypter {
    key: Option<BcryptAesGcmKey>,
    iv: Iv,
}

impl BcryptAesGcmEncrypter {
    fn new(key: AeadKey, iv: Iv) -> Self {
        Self {
            key: BcryptAesGcmKey::new(key),
            iv,
        }
    }
}

impl MessageEncrypter for BcryptAesGcmEncrypter {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let key = self.key.as_ref().ok_or(Error::EncryptError)?;
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut plaintext = msg.payload.to_vec();
        plaintext.push(msg.typ.into());
        let mut ciphertext = vec![0u8; plaintext.len()];
        let mut tag = [0u8; 16];
        let mut nonce = Nonce::new(&self.iv, seq).0;
        let aad = make_tls13_aad(total_len);
        let mut auth_info = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO::for_encrypt(&mut nonce, &mut tag);
        auth_info.pbAuthData = aad.as_ptr() as *mut u8;
        auth_info.cbAuthData = aad.len() as u32;
        let mut written = 0u32;
        let status = unsafe {
            BCryptEncrypt(
                key.0,
                plaintext.as_ptr(),
                plaintext.len() as u32,
                &auth_info as *const _ as *const core::ffi::c_void,
                core::ptr::null_mut(),
                0,
                ciphertext.as_mut_ptr(),
                ciphertext.len() as u32,
                &mut written,
                0,
            )
        };
        if status < 0 {
            return Err(Error::EncryptError);
        }
        ciphertext.truncate(written as usize);
        ciphertext.extend_from_slice(&tag);
        Ok(OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            PrefixedPayload::from(ciphertext.as_slice()),
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + 16
    }
}

pub struct BcryptAesGcmDecrypter {
    key: Option<BcryptAesGcmKey>,
    iv: Iv,
}

impl BcryptAesGcmDecrypter {
    fn new(key: AeadKey, iv: Iv) -> Self {
        Self {
            key: BcryptAesGcmKey::new(key),
            iv,
        }
    }
}

impl MessageDecrypter for BcryptAesGcmDecrypter {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let key = self.key.as_ref().ok_or(Error::DecryptError)?;
        if msg.payload.len() < 16 {
            return Err(Error::DecryptError);
        }
        let ciphertext_len = msg.payload.len() - 16;
        let (ciphertext, tag) = msg.payload.split_at_mut(ciphertext_len);
        let nonce = Nonce::new(&self.iv, seq).0;
        let auth_info = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO::for_decrypt(&nonce, tag);
        let mut plaintext = vec![0u8; ciphertext_len];
        let mut written = 0u32;
        let status = unsafe {
            BCryptDecrypt(
                key.0,
                ciphertext.as_ptr(),
                ciphertext.len() as u32,
                &auth_info as *const _ as *const core::ffi::c_void,
                core::ptr::null_mut(),
                0,
                plaintext.as_mut_ptr(),
                plaintext.len() as u32,
                &mut written,
                0,
            )
        };
        if status < 0 {
            return Err(Error::DecryptError);
        }
        ciphertext[..written as usize].copy_from_slice(&plaintext[..written as usize]);
        msg.payload.truncate(written as usize);
        msg.into_tls13_unpadded_message()
    }
}

#[derive(Debug)]
pub struct BcryptKxGroup {
    group: NamedGroup,
    bcrypt_algorithm: BcryptAlgorithm,
    public_magic: u32,
    coordinate_size: usize,
    key_bits: u32,
}

impl BcryptKxGroup {
    pub const fn p256() -> Self {
        Self {
            group: NamedGroup::secp256r1,
            bcrypt_algorithm: BcryptAlgorithm::EcdhP256,
            public_magic: BCRYPT_ECDH_PUBLIC_P256_MAGIC,
            coordinate_size: 32,
            key_bits: 256,
        }
    }

    pub const fn p384() -> Self {
        Self {
            group: NamedGroup::secp384r1,
            bcrypt_algorithm: BcryptAlgorithm::EcdhP384,
            public_magic: BCRYPT_ECDH_PUBLIC_P384_MAGIC,
            coordinate_size: 48,
            key_bits: 384,
        }
    }
}

impl SupportedKxGroup for BcryptKxGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let mut key_handle: BCRYPT_KEY_HANDLE = core::ptr::null_mut();
        let generate_status = unsafe {
            BCryptGenerateKeyPair(self.bcrypt_algorithm.handle(), &mut key_handle, self.key_bits, 0)
        };
        if generate_status < 0 {
            return Err(Error::General("BCryptGenerateKeyPair failed".into()));
        }

        let finalize_status = unsafe { BCryptFinalizeKeyPair(key_handle, 0) };
        if finalize_status < 0 {
            unsafe {
                BCryptDestroyKey(key_handle);
            }
            return Err(Error::General("BCryptFinalizeKeyPair failed".into()));
        }

        let public_key = export_tls_key_share(key_handle, self.coordinate_size)?;

        Ok(Box::new(BcryptActiveKeyExchange {
            group: self.group,
            public_magic: self.public_magic,
            coordinate_size: self.coordinate_size,
            key_handle,
            public_key,
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
    public_magic: u32,
    coordinate_size: usize,
    key_handle: BCRYPT_KEY_HANDLE,
    public_key: Vec<u8>,
}

unsafe impl Send for BcryptActiveKeyExchange {}
unsafe impl Sync for BcryptActiveKeyExchange {}

impl ActiveKeyExchange for BcryptActiveKeyExchange {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        let peer = import_tls_key_share(self.public_magic, self.coordinate_size, peer_pub_key)?;
        let mut secret: BCRYPT_SECRET_HANDLE = core::ptr::null_mut();
        let agreement_status = unsafe { BCryptSecretAgreement(self.key_handle, peer.0, &mut secret, 0) };
        if agreement_status < 0 {
            return Err(Error::General("BCryptSecretAgreement failed".into()));
        }

        let mut secret_size = 0u32;
        let size_status = unsafe {
            BCryptDeriveKey(
                secret,
                BCRYPT_KDF_RAW_SECRET.as_ptr(),
                core::ptr::null(),
                core::ptr::null_mut(),
                0,
                &mut secret_size,
                0,
            )
        };
        if size_status < 0 {
            unsafe {
                BCryptDestroySecret(secret);
            }
            return Err(Error::General("BCryptDeriveKey size query failed".into()));
        }

        let mut secret_bytes = vec![0u8; secret_size as usize];
        let derive_status = unsafe {
            BCryptDeriveKey(
                secret,
                BCRYPT_KDF_RAW_SECRET.as_ptr(),
                core::ptr::null(),
                secret_bytes.as_mut_ptr(),
                secret_bytes.len() as u32,
                &mut secret_size,
                0,
            )
        };
        unsafe {
            BCryptDestroySecret(secret);
        }
        if derive_status < 0 {
            return Err(Error::General("BCryptDeriveKey failed".into()));
        }
        secret_bytes.resize(secret_size as usize, 0);
        Ok(SharedSecret::from(secret_bytes))
    }

    fn pub_key(&self) -> &[u8] {
        &self.public_key
    }

    fn group(&self) -> NamedGroup {
        self.group
    }
}

impl Drop for BcryptActiveKeyExchange {
    fn drop(&mut self) {
        unsafe {
            BCryptDestroyKey(self.key_handle);
        }
    }
}

struct BcryptKeyHandle(BCRYPT_KEY_HANDLE);

unsafe impl Send for BcryptKeyHandle {}
unsafe impl Sync for BcryptKeyHandle {}

impl Drop for BcryptKeyHandle {
    fn drop(&mut self) {
        unsafe {
            BCryptDestroyKey(self.0);
        }
    }
}

fn export_tls_key_share(key: BCRYPT_KEY_HANDLE, coordinate_size: usize) -> Result<Vec<u8>, Error> {
    let mut blob_size = 0u32;
    let size_status = unsafe {
        BCryptExportKey(
            key,
            core::ptr::null_mut(),
            BCRYPT_ECCPUBLIC_BLOB.as_ptr(),
            core::ptr::null_mut(),
            0,
            &mut blob_size,
            0,
        )
    };
    if size_status < 0 {
        return Err(Error::General("BCryptExportKey size query failed".into()));
    }

    let mut blob = vec![0u8; blob_size as usize];
    let export_status = unsafe {
        BCryptExportKey(
            key,
            core::ptr::null_mut(),
            BCRYPT_ECCPUBLIC_BLOB.as_ptr(),
            blob.as_mut_ptr(),
            blob.len() as u32,
            &mut blob_size,
            0,
        )
    };
    if export_status < 0 {
        return Err(Error::General("BCryptExportKey failed".into()));
    }
    blob.resize(blob_size as usize, 0);

    let expected_size = 8 + (coordinate_size * 2);
    if blob.len() != expected_size {
        return Err(Error::General("unexpected BCrypt ECC public blob size".into()));
    }

    let mut key_share = Vec::with_capacity(1 + coordinate_size * 2);
    key_share.push(0x04);
    key_share.extend_from_slice(&blob[8..]);
    Ok(key_share)
}

fn import_tls_key_share(
    public_magic: u32,
    coordinate_size: usize,
    peer_pub_key: &[u8],
) -> Result<BcryptKeyHandle, Error> {
    if peer_pub_key.len() != 1 + coordinate_size * 2 || peer_pub_key[0] != 0x04 {
        return Err(Error::General("invalid TLS ECDHE key share".into()));
    }

    let mut blob = Vec::with_capacity(8 + coordinate_size * 2);
    blob.extend_from_slice(&public_magic.to_le_bytes());
    blob.extend_from_slice(&(coordinate_size as u32).to_le_bytes());
    blob.extend_from_slice(&peer_pub_key[1..]);

    let mut key: BCRYPT_KEY_HANDLE = core::ptr::null_mut();
    let status = unsafe {
        BCryptImportKeyPair(
            match coordinate_size {
                32 => BCRYPT_ECDH_P256_ALG_HANDLE,
                48 => BCRYPT_ECDH_P384_ALG_HANDLE,
                _ => return Err(Error::General("unsupported ECDHE group".into())),
            },
            core::ptr::null_mut(),
            BCRYPT_ECCPUBLIC_BLOB.as_ptr(),
            &mut key,
            blob.as_ptr(),
            blob.len() as u32,
            0,
        )
    };
    if status < 0 {
        return Err(Error::General("BCryptImportKeyPair failed".into()));
    }

    Ok(BcryptKeyHandle(key))
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

#[derive(Clone)]
pub struct PinnedServerVerifier {
    pinned_leaf_sha256: [u8; 32],
}

impl PinnedServerVerifier {
    pub const fn new(pinned_leaf_sha256: [u8; 32]) -> Self {
        Self { pinned_leaf_sha256 }
    }
}

impl fmt::Debug for PinnedServerVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinnedServerVerifier").finish()
    }
}

impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let actual = SHA256.hash(end_entity.as_ref());
        if actual.as_ref() == self.pinned_leaf_sha256 {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(Error::General("server certificate pin mismatch".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        Err(Error::General("TLS 1.2 is not supported".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_rsa_sha256_signature(message, cert.as_ref(), dss)?;
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        Vec::from([
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
        ])
    }
}

fn verify_rsa_sha256_signature(
    message: &[u8],
    cert_der: &[u8],
    dss: &DigitallySignedStruct,
) -> Result<(), Error> {
    let (modulus, exponent) = rsa_public_key_from_certificate(cert_der)?;
    let rsa_key = import_rsa_public_key(modulus, exponent)?;
    let digest = SHA256.hash(message);

    match dss.scheme {
        SignatureScheme::RSA_PSS_SHA256 => {
            let padding = BcryptPssPaddingInfo {
                psz_alg_id: BCRYPT_SHA256_ALGORITHM.as_ptr(),
                cb_salt: 32,
            };
            let status = unsafe {
                BCryptVerifySignature(
                    rsa_key.0,
                    &padding as *const _ as *const core::ffi::c_void,
                    digest.as_ref().as_ptr(),
                    digest.as_ref().len() as u32,
                    dss.signature().as_ptr(),
                    dss.signature().len() as u32,
                    BCRYPT_PAD_PSS,
                )
            };
            if status < 0 {
                return Err(Error::General("BCrypt RSA-PSS verify failed".into()));
            }
            Ok(())
        }
        SignatureScheme::RSA_PKCS1_SHA256 => {
            let padding = BcryptPkcs1PaddingInfo {
                psz_alg_id: BCRYPT_SHA256_ALGORITHM.as_ptr(),
            };
            let status = unsafe {
                BCryptVerifySignature(
                    rsa_key.0,
                    &padding as *const _ as *const core::ffi::c_void,
                    digest.as_ref().as_ptr(),
                    digest.as_ref().len() as u32,
                    dss.signature().as_ptr(),
                    dss.signature().len() as u32,
                    BCRYPT_PAD_PKCS1,
                )
            };
            if status < 0 {
                return Err(Error::General("BCrypt RSA-PKCS1 verify failed".into()));
            }
            Ok(())
        }
        _ => Err(Error::General("unsupported TLS 1.3 signature scheme".into())),
    }
}

fn import_rsa_public_key(modulus: &[u8], exponent: &[u8]) -> Result<BcryptKeyHandle, Error> {
    let modulus = trim_leading_zero(modulus);
    let exponent = trim_leading_zero(exponent);
    let bit_len = (modulus.len() * 8) as u32;

    let mut blob = Vec::with_capacity(24 + exponent.len() + modulus.len());
    blob.extend_from_slice(&BCRYPT_RSAPUBLIC_MAGIC.to_le_bytes());
    blob.extend_from_slice(&bit_len.to_le_bytes());
    blob.extend_from_slice(&(exponent.len() as u32).to_le_bytes());
    blob.extend_from_slice(&(modulus.len() as u32).to_le_bytes());
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(&0u32.to_le_bytes());
    blob.extend_from_slice(exponent);
    blob.extend_from_slice(modulus);

    let mut key: BCRYPT_KEY_HANDLE = core::ptr::null_mut();
    let status = unsafe {
        BCryptImportKeyPair(
            BCRYPT_RSA_ALG_HANDLE,
            core::ptr::null_mut(),
            BCRYPT_RSAPUBLIC_BLOB.as_ptr(),
            &mut key,
            blob.as_ptr(),
            blob.len() as u32,
            0,
        )
    };
    if status < 0 {
        return Err(Error::General("BCrypt RSA public key import failed".into()));
    }
    Ok(BcryptKeyHandle(key))
}

fn trim_leading_zero(mut value: &[u8]) -> &[u8] {
    while value.len() > 1 && value[0] == 0 {
        value = &value[1..];
    }
    value
}

fn rsa_public_key_from_certificate(cert: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    let mut reader = DerReader::new(cert);
    let certificate = reader.read_tlv(0x30)?;
    let mut certificate_reader = DerReader::new(certificate);
    let tbs = certificate_reader.read_tlv(0x30)?;
    let mut tbs_reader = DerReader::new(tbs);

    if tbs_reader.peek_tag() == Some(0xa0) {
        tbs_reader.read_tlv(0xa0)?;
    }

    tbs_reader.read_tlv(0x02)?; // serial
    tbs_reader.read_tlv(0x30)?; // signature algorithm
    tbs_reader.read_tlv(0x30)?; // issuer
    tbs_reader.read_tlv(0x30)?; // validity
    tbs_reader.read_tlv(0x30)?; // subject
    let spki = tbs_reader.read_tlv(0x30)?;
    let mut spki_reader = DerReader::new(spki);
    spki_reader.read_tlv(0x30)?; // algorithm
    let bit_string = spki_reader.read_tlv(0x03)?;
    if bit_string.is_empty() || bit_string[0] != 0 {
        return Err(Error::General("invalid RSA SPKI bit string".into()));
    }

    let mut rsa_reader = DerReader::new(&bit_string[1..]);
    let rsa_public_key = rsa_reader.read_tlv(0x30)?;
    let mut rsa_public_key_reader = DerReader::new(rsa_public_key);
    let modulus = rsa_public_key_reader.read_tlv(0x02)?;
    let exponent = rsa_public_key_reader.read_tlv(0x02)?;
    Ok((modulus, exponent))
}

struct DerReader<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> DerReader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn peek_tag(&self) -> Option<u8> {
        self.input.get(self.offset).copied()
    }

    fn read_tlv(&mut self, expected_tag: u8) -> Result<&'a [u8], Error> {
        let tag = *self
            .input
            .get(self.offset)
            .ok_or_else(|| Error::General("truncated DER tag".into()))?;
        if tag != expected_tag {
            return Err(Error::General("unexpected DER tag".into()));
        }
        self.offset += 1;

        let length = self.read_len()?;
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| Error::General("DER length overflow".into()))?;
        if end > self.input.len() {
            return Err(Error::General("truncated DER value".into()));
        }

        let value = &self.input[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn read_len(&mut self) -> Result<usize, Error> {
        let first = *self
            .input
            .get(self.offset)
            .ok_or_else(|| Error::General("truncated DER length".into()))?;
        self.offset += 1;

        if first & 0x80 == 0 {
            return Ok(first as usize);
        }

        let count = (first & 0x7f) as usize;
        if count == 0 || count > core::mem::size_of::<usize>() {
            return Err(Error::General("unsupported DER length".into()));
        }

        let mut length = 0usize;
        for _ in 0..count {
            let byte = *self
                .input
                .get(self.offset)
                .ok_or_else(|| Error::General("truncated DER long length".into()))?;
            self.offset += 1;
            length = (length << 8) | byte as usize;
        }
        Ok(length)
    }
}
