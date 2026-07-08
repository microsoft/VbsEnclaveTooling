# C++ mbedTLS server-auth sample

This directory contains the C++ mbedTLS server-auth validation tools. The host-mode harness exercises the C++ mbedTLS driver without loading an enclave. The `TlsEnclave` and `TlsHost` projects run the same driver behind generated `TlsTransport.edl` VTL0/VTL1 bindings.

The enclave owns all server-identity policy — the connection target, expected hostname/SNI, HTTP path, the pinned leaf-certificate SHA-256, and the response-size limit — via a scenario table keyed by an opaque `scenario_id`. The pinned certificate is generated into the enclave image at build time (`ScenarioPolicy.g.h`). VTL0 only provides transport and selects a scenario by id; it cannot supply or relax any policy. The enclave connects to the local TLS test server, negotiates TLS 1.3, fetches `/secret-config`, and returns only a bounded derived result.

## Prerequisites

Run all sample scripts with **PowerShell 7+ (`pwsh`)** — they use .NET APIs not present in Windows PowerShell 5.1. Builds target `x64` or `ARM64`.

## Build

```powershell
.\Build-HandshakeHarness.ps1 -Configuration Debug -Platform ARM64
```

## Host-mode harness

The one-shot harness test generates certs, builds the harness, starts the local test server, and runs both a positive case (valid pin is accepted) and a negative case (a mismatched pin is rejected). The platform is detected automatically.

```powershell
.\Test-HandshakeHarness.ps1
```

Expected result (positive case):

```text
status=0
decision=Allow
output_value=1406
tls_version=0x304
cipher_suite=0x1302
```

## Real enclave host

The real enclave flow builds and signs `TlsEnclave.dll`, builds `TlsHost.exe`, starts the local TLS 1.3 test server, and drives the enclave's scenario state machine (`StartScenario` → `DriveConnection` → `GetDerivedResult` → `CloseScenario`) across the VTL0/VTL1 boundary.

> **Note:** loading a signed enclave requires the signing certificate to be trusted and, for locally self-signed development certificates, an enclave-development / test-signing configuration. Do this on a suitably configured VM — not a production machine.

Provision and trust the signing certificate **first** (this creates the cert if it does not exist), then build and sign:

```powershell
# 1. Create + trust the enclave signing certificate (approve the trust prompt).
..\TlsEnclave\Add-TrustedCert.ps1

# 2. Build the enclave (also generates the build-time certificate pin) and sign it.
..\TlsEnclave\Build-TlsEnclave.ps1 -Configuration Debug -Platform ARM64
..\TlsEnclave\Sign-TlsEnclave.ps1  -Configuration Debug -Platform ARM64 -CertName TlsSampleEnclaveCert

# 3. Build the host.
..\TlsHost\Build-TlsHost.ps1 -Configuration Debug -Platform ARM64
```

A signing certificate already present in `Cert:\CurrentUser\My` may instead be selected by thumbprint:

```powershell
..\TlsEnclave\Sign-TlsEnclave.ps1 -Configuration Debug -Platform ARM64 -CertThumbprint <thumbprint>
```

Remove the current-user trust entry when finished:

```powershell
..\TlsEnclave\Remove-TrustedCert.ps1
```

Start the test server (the enclave connects to `127.0.0.1:9781` for scenario 0):

```powershell
$repo = (Get-Location).Path

.\SampleApps\Tls\TestServer\Start-TestServer.ps1 `
  -StopExisting `
  -Address 127.0.0.1 `
  -Port 9781 `
  -CertificatePath "$repo\SampleApps\Tls\TestServer\test-certs\server.pfx"
```

In another shell, run the host with the enclave DLL, the scenario id, and the application input value:

```powershell
& "$repo\SampleApps\Tls\Cpp\TlsHost\bin\ARM64\Debug\TlsHost.exe" `
  "$repo\SampleApps\Tls\Cpp\TlsEnclave\bin\ARM64\Debug\TlsEnclave.dll" `
  0 `
  38
```

Expected result: `status=0`, `decision=Allow`, `output_value=1406`.
