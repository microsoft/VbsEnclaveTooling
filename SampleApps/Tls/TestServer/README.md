# TLS sample test server

This utility provides the deterministic local endpoint used by the TLS enclave samples.

The server is TLS 1.3-only by default and serves a fixed secret payload at `/secret-config`. The enclave samples should consume that payload inside VTL1 and return only derived results to VTL0.

## Prerequisites

Run these scripts with **PowerShell 7+ (`pwsh`)**; they use .NET APIs (`X509Certificate2.CreateFromPem`, `SHA256.HashData`, PEM export) that are not available in Windows PowerShell 5.1.

## Generate test certificates

```powershell
.\generate-test-certs.ps1
```

This creates:

- `test-certs\server-cert.pem`
- `test-certs\server-key.pem`
- `test-certs\server.pfx`
- `test-certs\client-cert.pem`
- `test-certs\client-key.pem`
- `test-certs\client.pfx`

The first sample uses the server certificate for server-auth TLS. The client certificate files are generated now so the later mutual-auth profile can use the same test-server layout.

## Run

```powershell
.\Start-TestServer.ps1 -Address 127.0.0.1 -Port 9781
```

Use port `9781` to match the endpoint the enclave samples pin for scenario 0 (see `Cpp\TlsEnclave\ScenarioPolicy.g.h`); the server's own default is `8443`, which the sample enclave does not connect to.

By default this opens the server in a new PowerShell window. Close that window, or stop its PID, to stop the server.

For manual testing, prefer absolute certificate paths so the child PowerShell window cannot resolve paths relative to a different working directory. Run this from the `TestServer` directory:

```powershell
$certs = Join-Path (Get-Location).Path "test-certs"

.\Start-TestServer.ps1 `
  -StopExisting `
  -Address 127.0.0.1 `
  -Port 9781 `
  -CertificatePath "$certs\server-cert.pem" `
  -CertificateKeyPath "$certs\server-key.pem"
```

The server prints the certificate path and SHA-256 hash it loaded:

```text
server_cert_path=...
server_cert_sha256=...
```

Then request:

```text
GET /secret-config HTTP/1.1
Host: localhost
Connection: close
```

The server logs the negotiated TLS version and cipher suite for protocol verification.
