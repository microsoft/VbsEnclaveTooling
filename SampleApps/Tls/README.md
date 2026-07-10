# TLS enclave samples

These samples demonstrate how a VTL1 enclave can fetch data from a TLS endpoint while VTL0 only provides transport I/O.

The staged implementation plan and security model are documented in [`..\..\docs\TlsEnclaveSamples.md`](..\..\docs\TlsEnclaveSamples.md).

## Layout

| Path | Purpose |
|---|---|
| `TlsTransport.edl` | Shared transport and scenario contract used by the C++ and Rust samples. |
| `TestServer` | Local TLS 1.3 test server and certificate generator. |
| `Scripts` | Shared, language-neutral helper scripts (enclave signing-certificate provisioning) used by the C++ and Rust samples. |
| `Cpp\Common` | Shared C++ mbedTLS driver and enclave-oriented mbedTLS configuration. |
| `Cpp\Tls.sln` | Visual Studio solution that builds the enclave and host. |
| `Cpp\TlsEnclave` | VBS enclave DLL that runs the mbedTLS TLS 1.3 client behind generated EDL callbacks. |
| `Cpp\TlsHost` | Host application that loads `TlsEnclave.dll`, registers VTL0 TCP callbacks, and calls into VTL1. |

The C++ server-auth TLS sample is implemented. The host/enclave EDL bindings are generated at build time from the `Microsoft.Windows.VbsEnclave.CodeGenerator` NuGet package (into each project's ignored `Generated Files` directory) rather than checked in. Rust, mutual-auth, and embedded-attestation samples will be added in later branches. They should reuse the shared EDL contract rather than inventing separate transport callback shapes.

## Prerequisites

- Run all sample scripts with **PowerShell 7+ (`pwsh`)** — they use .NET APIs not present in Windows PowerShell 5.1, and the enclave build invokes `pwsh` for its pre-build pin generation and post-build signing.
- Loading a signed enclave requires the signing certificate to be trusted and, for locally self-signed development certificates, an enclave-development / test-signing configuration. Do this on a suitably configured VM — not a production machine.

## Build and run

Provision the signing certificate once, and fetch the pinned mbedTLS source (both are one-time per machine):

```powershell
# Create + trust the enclave signing certificate 'CN=TlsSampleEnclaveCert' (approve the trust prompt).
.\Scripts\Add-TrustedSigningCert.ps1

# Fetch pinned mbedTLS source into the git-ignored SampleApps\Tls\external\mbedtls.
.\Fetch-MbedTls.ps1
```

The enclave build pins the SHA-256 of the test server's leaf certificate into the image. It runs `TestServer\generate-test-certs.ps1` automatically when `test-certs\server-cert.pem` is not already present, so the certificates the server command below refers to are produced by the build — you do not need to generate them separately.

Then build the solution — either open `Cpp\Tls.sln` in Visual Studio, or from a developer command prompt:

```powershell
msbuild .\Cpp\Tls.sln /restore /p:RestorePackagesConfig=true /p:Configuration=Debug /p:Platform=x64
```

The build generates the EDL bindings and the certificate pin (`ScenarioPolicy.g.h`), compiles the enclave and host, and — as a post-build step — applies VEIID protection and signs `TlsEnclave.dll` with `CN=TlsSampleEnclaveCert`. If that certificate is missing, the build stops early with a message telling you to run `Scripts\Add-TrustedSigningCert.ps1`.

Start the test server (the enclave connects to `127.0.0.1:9781` for scenario 0):

```powershell
.\TestServer\Start-TestServer.ps1 -StopExisting -Address 127.0.0.1 -Port 9781 `
  -CertificatePath .\TestServer\test-certs\server-cert.pem `
  -CertificateKeyPath .\TestServer\test-certs\server-key.pem
```

In another shell, run the host with the enclave DLL, the scenario id, and the application input value:

```powershell
.\Cpp\TlsHost\bin\x64\Debug\TlsHost.exe .\Cpp\TlsEnclave\bin\x64\Debug\TlsEnclave.dll 0 38
```

Expected result: `status=0`, `decision=Allow`, `output_value=1406`, `tls_version=0x304` (TLS 1.3). When finished, remove the current-user trust entry with `Scripts\Remove-TrustedSigningCert.ps1`.
