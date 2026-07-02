# TLS enclave samples

These samples demonstrate how a VTL1 enclave can fetch data from a TLS endpoint while VTL0 only provides transport I/O.

The staged implementation plan and security model are documented in [`..\..\docs\TlsEnclaveSamples.md`](..\..\docs\TlsEnclaveSamples.md).

## Layout

| Path | Purpose |
|---|---|
| `TlsTransport.edl` | Shared transport and scenario contract used by the C++ and Rust samples. |
| `TestServer` | Local TLS 1.3 test server and certificate generator. |
| `Cpp\Common` | Shared C++ mbedTLS driver and enclave-oriented mbedTLS configuration. |
| `Cpp\HandshakeHarness` | Host-mode harness for exercising the C++ mbedTLS driver before loading an enclave. |
| `Cpp\TlsEnclave` | VBS enclave DLL that runs the mbedTLS TLS 1.3 client behind generated EDL callbacks. |
| `Cpp\TlsHost` | Host application that loads `TlsEnclave.dll`, registers VTL0 TCP callbacks, and calls into VTL1. |
| `Cpp\Generated` | Checked-in C++ bindings generated from `TlsTransport.edl`. |

The C++ server-auth TLS sample is implemented. Rust, mutual-auth, and embedded-attestation samples will be added in later branches. They should reuse the shared EDL contract rather than inventing separate transport callback shapes.
