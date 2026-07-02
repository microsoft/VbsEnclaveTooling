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

The crate also contains a non-functional `bcrypt_provider` skeleton that compiles the public rustls provider trait surface without enabling built-in crypto providers.
