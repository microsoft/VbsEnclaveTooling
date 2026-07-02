# TLS enclave samples plan

This document stages a set of TLS samples that demonstrate how a VTL1 enclave can fetch data from a web server while VTL0 only provides transport I/O.

The samples are TLS client samples: the enclave initiates the TLS connection to a server. VTL0 may resolve names, create sockets, and move bytes, but TLS terminates inside VTL1.

## Goals

- Keep TLS session keys, decrypted server data, and client private keys inside VTL1.
- Let VTL0 tunnel encrypted TCP bytes without trusting it with web payload data.
- Show the same security profiles in C++ with mbedTLS and Rust with rustls.
- Use deterministic local tests before relying on public internet endpoints.
- Document which guarantees the samples do and do not provide.

## Non-goals

- Implement a browser-equivalent public PKI stack.
- Support TLS 1.0 or TLS 1.1.
- Support TLS 1.4 before it is standardised.
- Return server response plaintext directly to VTL0 in the secure samples.
- Prevent VTL0 from denying service, delaying traffic, resetting sockets, or observing metadata.

## Sample matrix

| Profile | C++ enclave | Rust enclave | Main guarantee |
|---|---|---|---|
| Server-auth TLS | mbedTLS | rustls | VTL1 validates the server and consumes server data while VTL0 only tunnels ciphertext. |
| Mutual-auth TLS | mbedTLS | rustls | The server releases data only to a TLS client credential whose private key is held in VTL1. |
| Server-auth TLS with embedded attestation | mbedTLS | rustls | The server validates enclave evidence inside the TLS channel before releasing data. |

Each profile should use TLS 1.3 by default. TLS 1.2 can be added later only as an explicit compatibility profile with ECDHE and AEAD cipher suites.

## Trust boundary

VTL0 is untrusted for confidentiality and integrity of application data. It may:

- Choose when to call into the enclave.
- Resolve DNS and connect sockets.
- Fragment, coalesce, delay, replay, drop, or corrupt transport bytes.
- Observe server name, IP address, timing, byte counts, connection success or failure, and derived enclave outputs.
- Log all bytes that cross the VTL0/VTL1 transport boundary.

VTL1 owns:

- TLS protocol state.
- TLS client randoms, traffic secrets, and decrypted records.
- Server identity validation policy.
- Client private keys for mutual-auth TLS.
- Attestation evidence generation for the embedded-attestation profile.
- HTTP request construction, HTTP response parsing, and application logic that consumes the server payload.

The VTL0/VTL1 transport boundary carries encrypted TLS bytes only. Server response plaintext must not cross that boundary in the secure samples.

## Derived-result contract

The sample server should return a payload that materially affects enclave behaviour, for example:

```json
{
  "operation": "scale-if-even",
  "multiplier": 37,
  "secretLabel": "sample-server-only-value"
}
```

The enclave consumes this payload and returns only a derived result, such as:

```text
decision = Allow
outputValue = 1369
diagnostics = TLS1.3, TLS_AES_128_GCM_SHA256, server-auth-ok
```

The payload itself, including sentinel strings used by tests, must never be returned directly to VTL0.

## Certificate and identity validation

The first server-auth sample should use a pinned server SPKI or pinned leaf certificate stored in VTL1 policy. This avoids depending on a host-supplied trust store, untrusted host time, AIA fetching, CRL fetching, or OCSP.

Later samples may add embedded trust anchors, but the trust anchors must be measured into the enclave image or provisioned as sealed VTL1 policy. VTL0 must not be able to relax server validation policy at runtime.

The mutual-auth profile proves possession of a VTL1-held client private key. It does not, by itself, prove that the key belongs to a specific enclave build unless the credential was issued or provisioned based on attestation.

The embedded-attestation profile should bind enclave evidence to:

- A fresh server nonce.
- The TLS session, using a TLS exporter or equivalent channel binding when available.
- The enclave policy hash.
- The requested server name.
- Any enclave-held public key that will be used for follow-on authorisation.

## Time, revocation, and entropy

Host-supplied time is advisory. It can drive non-security timers and test deadlines, but cannot by itself justify certificate freshness, revocation freshness, or anti-replay freshness.

Until a trusted time and revocation source is available inside the enclave, the samples should avoid claiming browser-equivalent certificate validation. Pinned server identity is the primary validation mode for the first sample.

The TLS implementations must use enclave-compatible entropy. P3 and P4 should include early build spikes that prove the chosen mbedTLS and rustls crypto providers can build and run in the VTL1 environment.

## Shared transport shape

The EDL contract in later phases should model VTL0 as a bounded, non-blocking transport provider:

```text
trusted VTL0 -> VTL1:
  StartScenario(...)
  DriveConnection(...)
  GetDerivedResult(...)
  Close(...)

untrusted VTL1 -> VTL0:
  HostTcpConnect(...)
  HostTcpRecv(...)
  HostTcpSend(...)
  HostTcpClose(...)
```

Callback results need at least `Ok`, `WouldBlock`, `Closed`, and `Failed`. The enclave driver must use operation budgets so a hostile or buggy host cannot trap VTL1 in an unbounded callback loop.

All handles crossing the EDL boundary must be opaque table handles validated in VTL1. They must not be raw VTL1 pointers.

## Branch staging

Each phase branch is stacked on the previous phase branch.

| Phase | Branch | Base | Contents |
|---|---|---|---|
| P0 | `user/gudge/tls-samples/p0-threat-model` | `main` | This threat model, scenario contract, staging plan, and security assertions. |
| P1 | `user/gudge/tls-samples/p1-test-server` | P0 | Shared TLS 1.3 test server, certificate generation, and deterministic payloads. |
| P2 | `user/gudge/tls-samples/p2-transport-edl` | P1 | Shared EDL transport contract and generated binding integration points. |
| P3 | `user/gudge/tls-samples/p3-mbedtls-feasibility` | P2 | mbedTLS C++ enclave feasibility study and integration recommendation. |
| P4 | `user/gudge/tls-samples/p4-cpp-server-auth` | P3 | C++ mbedTLS server-auth TLS sample. |
| P5 | `user/gudge/tls-samples/p5-rustls-feasibility` | P4 | rustls enclave feasibility study, including BCrypt-backed provider assessment. |
| P6 | `user/gudge/tls-samples/p6-rust-server-auth` | P5 | Rust rustls server-auth TLS sample. |
| P7 | `user/gudge/tls-samples/p7-mutual-auth` | P6 | C++ and Rust mutual-auth TLS profiles. |
| P8 | `user/gudge/tls-samples/p8-embedded-attestation` | P7 | C++ and Rust server-auth TLS with embedded enclave attestation. |
| P9 | `user/gudge/tls-samples/p9-verification-docs` | P8 | Cross-profile protocol verification, negative tests, and final documentation. |

Although some language-specific work could be developed independently, the staged branch stack keeps each phase reviewable as an incremental story.

## Current status

P4 has demonstrated the C++ server-auth path end-to-end on a VM configured to load VBS enclaves:

- `TlsHost.exe` loads `TlsEnclave.dll`.
- VTL0 registers the generated TCP callbacks from `TlsTransport.edl`.
- VTL1 runs the mbedTLS TLS 1.3 client handshake.
- VTL0 only performs TCP connect, send, receive, and close callbacks.
- VTL1 pins the test server certificate SHA-256 hash, fetches `/secret-config`, consumes the payload, and returns only the derived result.

The validated result is:

```text
status=0
decision=Allow
output_value=1406
diagnostics=TLSv1.3, TLS1-3-AES-256-GCM-SHA384, server-auth-ok
tls_version=0x304
cipher_suite=0x1302
```

## Required tests and verification

Every profile should have tests for:

- TLS 1.3 succeeds.
- TLS 1.2-only server fails in the default profile.
- Wrong server certificate or SPKI fails.
- Wrong hostname fails.
- Fragmented reads and writes succeed.
- `WouldBlock` during handshake and application data transfer succeeds.
- TCP close without TLS `close_notify` is reported as truncation.
- VTL0 captured only encrypted TLS records.
- Sentinel server payload strings do not appear in VTL0-visible outputs or logs.

Profile-specific tests:

| Profile | Required checks |
|---|---|
| Server-auth TLS | Server payload influences the derived enclave result without being returned. |
| Mutual-auth TLS | Server rejects missing or wrong client credentials and accepts the VTL1-held credential. |
| Embedded attestation | Server rejects stale nonce, wrong policy hash, wrong enclave identity or SVN, and channel-binding mismatch. |

The test server should record negotiated TLS version, cipher suite, ALPN selection if used, client-auth status, attestation status, and clean-close status. Enclave diagnostics may expose those protocol facts, but not server payload data.

## Security assertions

The completed samples should support these claims:

- VTL0 cannot read server response plaintext from the transport path.
- VTL0 cannot undetectably modify server data accepted by the enclave.
- VTL0 cannot substitute a different server when VTL1 pins or validates server identity.
- In the mutual-auth profile, the server can require possession of a VTL1-held client private key.
- In the embedded-attestation profile, the server can require approved enclave identity and policy before releasing data.

The samples should not claim:

- VTL0 cannot deny service, delay traffic, reset sockets, or observe metadata.
- Derived outputs reveal nothing about the server payload.
- Public PKI revocation and freshness are browser-equivalent without trusted time and revocation inputs.
- Mutual-auth TLS alone proves the client key is held by a specific enclave build.
