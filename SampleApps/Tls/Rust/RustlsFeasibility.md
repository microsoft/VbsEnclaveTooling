# rustls enclave feasibility

This note records the first Rust/rustls feasibility spike for the TLS enclave samples.

## Result

Result: **rustls core is feasible enough to proceed to a BCrypt-backed provider spike**.

The `SampleApps\Tls\Rust\RustlsFeasibility` crate builds as a `#![no_std]` + `alloc` crate with:

```toml
rustls = { version = "0.23", default-features = false }
```

The crate references `rustls::ClientConfig`, `rustls::RootCertStore`, and `rustls::crypto::CryptoProvider` without enabling rustls `std`, `ring`, or `aws-lc-rs` features.

The second P5 increment adds a BCrypt provider skeleton. It constructs a `CryptoProvider` and implements the public rustls trait surface needed for a future provider:

- `SecureRandom`
- `KeyProvider`
- `Hash` and hash context
- `Hmac` and HMAC key
- `Tls13AeadAlgorithm`, `MessageEncrypter`, and `MessageDecrypter`
- P-256/P-384 `SupportedKxGroup` and `ActiveKeyExchange`

The skeleton now includes real BCrypt-backed implementations for randomness, SHA-256/SHA-384 hashing, HMAC-SHA256/HMAC-SHA384, AES-256-GCM record protection, and P-256/P-384 ECDH key exchange. It also includes a pinned leaf-certificate verifier that hashes the server certificate DER with SHA-256 and verifies TLS 1.3 RSA/SHA-256 handshake signatures with BCrypt.

ECDSA handshake signature verification remains future work. The local .NET test server currently uses an RSA certificate, so RSA-PSS-SHA256 and RSA-PKCS1-SHA256 are enough for the first Rust server-auth path.

`SampleApps\Tls\Rust\RustlsHostHarness` builds a std host-mode harness around the same provider and the existing test server. The harness currently reaches the test server but fails during TLS record decryption, so the remaining runtime issue is in the rustls/BCrypt key schedule, ECDH secret formatting, or record-protection interop rather than in dependency selection.

## Dependency graph

The active dependency graph for the compile spike is:

```text
rustls-feasibility
└── rustls
    ├── once_cell
    ├── rustls-pki-types
    ├── rustls-webpki
    ├── subtle
    └── zeroize
```

`cargo tree -i ring`, `cargo tree -i getrandom`, and `cargo tree -i cc` print no active dependencies for this feature selection. `Cargo.lock` may still contain optional packages from rustls-webpki metadata, but they are not active in the selected build graph.

## Provider implication

rustls does not provide usable cryptography with default features disabled. A VTL1 sample must install or explicitly pass a custom `rustls::crypto::CryptoProvider`.

The provider must cover:

| rustls surface | BCrypt/enclave mapping |
|---|---|
| `SecureRandom` | `BCryptGenRandom(..., BCRYPT_USE_SYSTEM_PREFERRED_RNG)` |
| TLS 1.3 AEAD | AES-GCM via BCrypt authenticated cipher mode. ChaCha20-Poly1305 appears exposed in the enclave BCrypt surface but can be deferred if the test server negotiates AES-GCM. |
| Hash/HMAC/HKDF | SHA-256/SHA-384 and HMAC through BCrypt. rustls offers `HkdfUsingHmac`, so implementing `hmac::Hmac`/`hmac::Key` may be preferable to using BCrypt HKDF directly. |
| Key exchange | P-256/P-384 ECDH via BCrypt. X25519 is not available in the current enclave BCrypt surface. |
| Certificate and handshake signature verification | ECDSA/RSA verification through BCrypt. For the server-auth sample, use a custom verifier that pins the server leaf/SPKI and verifies the TLS 1.3 handshake signature. |
| Private-key signing | Needed later for mutual-auth, using BCrypt-backed ECDSA/RSA keys. |

## Constraints for P6

- Do not enable rustls `ring`, `aws-lc-rs`, or `std` features for the enclave crate.
- Do not advertise X25519 from the custom provider unless a separate enclave-compatible implementation is added.
- Prefer P-256/P-384 key exchange groups and confirm the test server accepts them.
- Keep public PKI freshness/revocation out of scope unless a trusted time/revocation source is added.
- Use a pinned-server verifier for the first Rust server-auth sample, matching the C++ sample threat model.

## Commands

```powershell
cargo build --manifest-path .\SampleApps\Tls\Rust\RustlsFeasibility\Cargo.toml
cargo tree --manifest-path .\SampleApps\Tls\Rust\RustlsFeasibility\Cargo.toml -e features
cargo tree --manifest-path .\SampleApps\Tls\Rust\RustlsFeasibility\Cargo.toml -i ring
cargo tree --manifest-path .\SampleApps\Tls\Rust\RustlsFeasibility\Cargo.toml -i getrandom
cargo tree --manifest-path .\SampleApps\Tls\Rust\RustlsFeasibility\Cargo.toml -i cc
```

## Remaining feasibility work

- Prove that the provider links into a Rust VTL1 enclave DLL.
- Add BCrypt ECDSA handshake signature verification for ECDSA server certificates.
- Fix the Rust host harness `DecryptError` against the .NET TLS test server.
- Once the host harness completes the handshake, move the same provider/driver into a Rust VTL1 enclave.
- Decide whether P-256 only is sufficient for the local test server or whether P-384 should be implemented in the first Rust sample.
