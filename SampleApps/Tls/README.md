# TLS enclave samples

These samples demonstrate how a VTL1 enclave can fetch data from a TLS endpoint while VTL0 only provides transport I/O.

The staged implementation plan and security model are documented in [`..\..\docs\TlsEnclaveSamples.md`](..\..\docs\TlsEnclaveSamples.md).

## Layout

| Path | Purpose |
|---|---|
| `TlsTransport.edl` | Shared transport and scenario contract used by the C++ and Rust samples. |
| `TestServer` | Local TLS 1.3 test server and certificate generator. |

The C++ and Rust enclave samples will be added in later branches. They should import or copy the shared EDL contract rather than inventing separate transport callback shapes.
