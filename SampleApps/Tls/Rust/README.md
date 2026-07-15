# Rust TLS enclave sample

This is the Rust counterpart to the C++ TLS server-auth sample. A VTL1 enclave
runs a rustls TLS 1.3 client to completion while VTL0 only tunnels transport
bytes, so TLS session keys and decrypted server data never leave the enclave and
only a bounded, derived result crosses back to the host. It **reuses the same
`..\TlsTransport.edl` contract** as the C++ sample rather than defining its own.

## Layout

| Path | Purpose |
|---|---|
| `RustlsFeasibility` | `no_std` + `alloc` crate: the BCrypt-backed rustls `CryptoProvider` (`bcrypt_provider`) and the shared unbuffered TLS driver (`tls_driver`). |
| `RustlsHostHarness` | `std` host-mode harness that runs the shared `tls_driver` against the test server over a socket — proves the enclave's TLS logic without the enclave. |
| `TlsEnclave` | VTL1 enclave (`cdylib`) implementing the trusted EDL surface; runs the driver, driving transport through the `HostTcp*` callbacks. |
| `TlsHost` | VTL0 host: loads the enclave, registers the socket transport callbacks, and calls into VTL1. |
| `Generate-And-Build.ps1` | Generates the Rust EDL binding crates, builds both crates, and (optionally) signs the enclave. |

The driver in `RustlsFeasibility::tls_driver` is the code that runs inside the
enclave. The only thing that differs between the host harness and the enclave is
the `TlsTransport` implementation (socket vs. `HostTcp*` EDL callbacks), so a
green host-harness run proves the enclave's TLS logic.

## Verification semantics

Matches the C++ sample: trust rests on the pinned leaf certificate (SHA-256 of
its DER) **and** the leaf being valid for the requested name (SAN). Certificate
time and issuer trust are deliberately not checked (the C++ sample compiles
mbedTLS time out entirely), so rustls is given a fixed stub time provider.

## Build

```powershell
# Provision the signing certificate once (shared with the C++ sample):
..\Scripts\Add-TrustedSigningCert.ps1

# Generate bindings, build both crates, and sign the enclave:
.\Generate-And-Build.ps1 -Configuration debug -CertName TlsSampleEnclaveCert
```

`Generate-And-Build.ps1` regenerates the EDL binding crates on every run (they
are not checked in) and applies a small fix-up for an upstream Rust-codegen bug
where the generated trusted stub names its internal variable `result`, colliding
with the EDL `result` out-parameter of `TlsSample_RunScenario`.

## Run

Start the test server on the pinned port (using the certificate the build pinned):

```powershell
..\TestServer\Start-TestServer.ps1 -StopExisting -Address 127.0.0.1 -Port 9781 `
  -CertificatePath ..\TestServer\test-certs\server-cert.pem `
  -CertificateKeyPath ..\TestServer\test-certs\server-key.pem
```

Then run the host with the signed enclave DLL, scenario id, and input value:

```powershell
.\TlsHost\target\debug\tls-sample-host.exe `
  .\TlsEnclave\target\debug\tls_sample_enclave.dll 0 38
```

The expected result matches the C++ sample: `status=0`, `decision=Allow`,
`output_value=1406`, `tls_version=0x304`, `cipher_suite=0x1302`.

## Status

- The host harness (`RustlsHostHarness`) runs the shared driver end-to-end with
  full parity, so the TLS logic is proven.
- The enclave and host crates build; the enclave is VEIID-provisioned and signed.
- **Working end-to-end:** the host loads the signed enclave and runs the
  server-auth scenario against the test server, returning `status=0`,
  `decision=Allow`, `output_value=1406`, `tls_version=0x304`,
  `cipher_suite=0x1302` — full parity with the C++ sample.

## Build note (Windows MAX_PATH)

On a deeply-cloned repo, `flatc` can fail with *"Unable to generate Rust for
FlatbufferTypes"* because the gen crate's `build.rs` writes into a very deep
`target\...\build\<crate>-<hash>\out\flatbuffer_gen\` path that exceeds the
260-char `MAX_PATH` limit. Build with a short `CARGO_TARGET_DIR` (e.g. `C:\t`)
or enable Windows long paths.
