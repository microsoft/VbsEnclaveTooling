# Rust rustls host harness

This host-mode harness exercises the Rust BCrypt-backed rustls provider against the local TLS 1.3 test server before the provider is moved into a Rust VTL1 enclave.

## Build

```powershell
.\Build-RustlsHostHarness.ps1
```

## Test

```powershell
.\Test-RustlsHostHarness.ps1 -Port 9790
```

Current status: the harness builds and reaches the server, but the TLS handshake fails with `DecryptError`. The remaining runtime issue is likely in key schedule/ECDH shared-secret formatting or record-protection interop.
