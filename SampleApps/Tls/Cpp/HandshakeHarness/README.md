# C++ mbedTLS server-auth sample

This directory contains the C++ mbedTLS server-auth validation tools. The host-mode harness exercises the C++ mbedTLS driver without loading an enclave. The `TlsEnclave` and `TlsHost` projects run the same driver behind generated `TlsTransport.edl` VTL0/VTL1 bindings.

It connects to the local TLS test server, pins the server leaf certificate SHA-256 hash, negotiates TLS 1.3, fetches `/secret-config`, and returns only a derived result.

## Build

```powershell
.\Build-HandshakeHarness.ps1 -Configuration Debug -Platform x64
```

## Host-mode harness

The one-shot harness test generates certs, builds the harness, starts the local test server, runs the harness, and verifies that the server certificate hash matches the pinned hash:

```powershell
.\Test-HandshakeHarness.ps1 -Port 9780
```

Expected result:

```text
status=0
decision=Allow
output_value=1406
diagnostics=TLSv1.3, TLS1-3-AES-256-GCM-SHA384, server-auth-ok
```

## Real enclave host

The real enclave flow builds and signs `TlsEnclave.dll`, builds `TlsHost.exe`, starts the local TLS 1.3 test server, and calls `TlsSample_RunScenario` in VTL1.

```powershell
..\TlsEnclave\Build-TlsEnclave.ps1 -Configuration Debug -Platform x64
..\TlsHost\Build-TlsHost.ps1 -Configuration Debug -Platform x64
..\TlsEnclave\Sign-TlsEnclave.ps1 -Configuration Debug -Platform x64 -CertName TlsSampleEnclaveCert
```

The signing certificate must be trusted by the machine for `LoadEnclaveImageW` to accept the enclave DLL. On a suitably configured VM, a valid enclave signing certificate may also be selected by thumbprint:

```powershell
..\TlsEnclave\Sign-TlsEnclave.ps1 -Configuration Debug -Platform x64 -CertThumbprint <thumbprint>
```

To add or remove the current-user trust entry for the sample cert:

```powershell
..\TlsEnclave\Add-TrustedCert.ps1
..\TlsEnclave\Remove-TrustedCert.ps1
```

Run the manual end-to-end flow from the repository root:

```powershell
$repo = (Get-Location).Path

.\SampleApps\Tls\TestServer\generate-test-certs.ps1

.\SampleApps\Tls\TestServer\Start-TestServer.ps1 `
  -StopExisting `
  -Address 127.0.0.1 `
  -Port 9789 `
  -CertificatePath "$repo\SampleApps\Tls\TestServer\test-certs\server-cert.pem" `
  -CertificateKeyPath "$repo\SampleApps\Tls\TestServer\test-certs\server-key.pem"
```

In another shell:

```powershell
& "$repo\SampleApps\Tls\Cpp\TlsHost\bin\x64\Debug\TlsHost.exe" `
  "$repo\SampleApps\Tls\Cpp\TlsEnclave\bin\x64\Debug\TlsEnclave.dll" `
  "$repo\SampleApps\Tls\TestServer\test-certs\server-cert.pem" `
  9789
```
