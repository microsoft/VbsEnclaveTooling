# Rust rustls host harness

This host-mode harness exercises the Rust BCrypt-backed rustls provider against the local TLS 1.3 test server before the provider is moved into a Rust VTL1 enclave.

## Build

```powershell
.\Build-RustlsHostHarness.ps1
```

## Run

```powershell
# args: <server-cert.pem> <port> <input-value> [server-name]
.\target\debug\rustls-host-harness.exe .\..\..\TestServer\test-certs\server-cert.pem 9781 38
```

The optional fourth argument overrides the SNI/hostname. Passing a name that is
not in the server certificate's SAN (for example `wrong.example.com`) exercises
the hostname/SAN rejection path and fails the run.

## Verification semantics

The driver matches the C++ sample: it trusts the exact pinned leaf certificate
(SHA-256 of its DER) **and** requires the leaf to be valid for the requested
name (SAN), while deliberately not checking certificate time or issuer trust.
`tests/pin_mismatch.rs` guards the pin rejection; a wrong-name run (above)
exercises the hostname rejection.

## Test

```powershell
.\Test-RustlsHostHarness.ps1 -Port 9790
```

Current status: the harness completes the TLS 1.3 handshake against the test
server and returns the derived result (`status=0`, `decision=Allow`,
`output_value=1406`) with `TLS_AES_256_GCM_SHA384`, matching the C++ sample.

The earlier `DecryptError` was a BCrypt ECDH byte-order bug: `BCRYPT_KDF_RAW_SECRET`
returns the shared secret little-endian, but TLS uses the big-endian X
coordinate, so the two peers derived mismatched key schedules. See
`tests/ecdh_roundtrip.rs` for the primitive-level regression guard; this
end-to-end test proves interop against a standard TLS stack.
