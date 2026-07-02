# rustls enclave feasibility

This crate is a compile spike for using rustls from a VTL1 Rust enclave.

It intentionally disables rustls default features so P5 can determine whether rustls core can be used from a `no_std` + `alloc` crate without silently pulling in `ring`, `aws-lc-rs`, `std`, or an OS RNG path.

## Build

```powershell
cargo build --manifest-path .\SampleApps\Tls\Rust\RustlsFeasibility\Cargo.toml
```

## Inspect dependencies

```powershell
cargo tree --manifest-path .\SampleApps\Tls\Rust\RustlsFeasibility\Cargo.toml -e features
cargo tree --manifest-path .\SampleApps\Tls\Rust\RustlsFeasibility\Cargo.toml -i ring
cargo tree --manifest-path .\SampleApps\Tls\Rust\RustlsFeasibility\Cargo.toml -i getrandom
```

The crate also contains a `bcrypt_provider` skeleton that compiles the public rustls provider trait surface without enabling built-in crypto providers. The skeleton currently includes real BCrypt-backed RNG, SHA-256/SHA-384, HMAC-SHA256/HMAC-SHA384, AES-256-GCM, P-256/P-384 ECDH, pinned leaf-certificate hash verification, and TLS 1.3 RSA/SHA-256 handshake signature verification.
