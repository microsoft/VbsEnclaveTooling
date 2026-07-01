# C++ mbedTLS handshake harness

This host-mode harness exercises the C++ mbedTLS driver that will later run behind `TlsTransport.edl` in VTL1.

It connects to the local TLS test server, pins the server leaf certificate SHA-256 hash, negotiates TLS 1.3, fetches `/secret-config`, and returns only a derived result.

## Build

```powershell
.\Build-HandshakeHarness.ps1 -Configuration Debug -Platform x64
```

## Run

Generate certificates and start the test server:

```powershell
..\..\TestServer\generate-test-certs.ps1
..\..\TestServer\Start-TestServer.ps1 -Address 127.0.0.1 -Port 8443
```

The server starts in a new PowerShell window.

## Real enclave host

The `TlsEnclave` and `TlsHost` projects build the same driver behind the generated VTL0/VTL1 bindings.

```powershell
..\TlsEnclave\Build-TlsEnclave.ps1 -Configuration Debug -Platform x64
..\TlsHost\Build-TlsHost.ps1 -Configuration Debug -Platform x64
..\TlsEnclave\Sign-TlsEnclave.ps1 -Configuration Debug -Platform x64 -CertName TlsSampleEnclaveCert
```

The signing certificate must be trusted by the machine for `LoadEnclaveImageW` to accept the enclave DLL.

To add or remove the current-user trust entry for the sample cert:

```powershell
..\TlsEnclave\Add-TrustedCert.ps1
..\TlsEnclave\Remove-TrustedCert.ps1
```

In another shell:

```powershell
.\bin\x64\Debug\HandshakeHarness.exe --cert ..\..\TestServer\test-certs\server-cert.pem --port 8443 --input 38
```
