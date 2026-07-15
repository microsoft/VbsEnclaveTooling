// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared `no_std` + `alloc` TLS 1.3 client driver.
//!
//! This drives rustls through its **unbuffered** connection API so the exact
//! code that runs inside the VTL1 enclave can also be exercised from the std
//! host harness. The only thing that differs between the two environments is
//! the [`TlsTransport`] implementation: the host harness moves bytes over a
//! real socket, while the enclave moves them through the generated `HostTcp*`
//! EDL callbacks into VTL0. rustls' buffered `ClientConnection`/`StreamOwned`
//! types are std-only, so they cannot be used from the enclave.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;

use rustls::client::UnbufferedClientConnection;
use rustls::pki_types::{ServerName, UnixTime};
use rustls::time_provider::TimeProvider;
use rustls::unbuffered::{AppDataRecord, ConnectionState, EncodeError, UnbufferedStatus};
use rustls::version::TLS13;
use rustls::ClientConfig;

use crate::bcrypt_provider::{provider_skeleton, PinnedServerVerifier};

/// Terminal status of a scenario run. Values mirror the EDL `TlsSampleStatus`
/// enum so the enclave can map them by value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScenarioStatus {
    Ok = 0,
    Closed = 1,
    Truncated = 2,
    ValidationFailed = 3,
    TransportFailed = 4,
    ProtocolFailed = 5,
    InvalidState = 8,
}

/// Enclave-owned scenario policy. VTL0 never supplies any of these; they are
/// baked into the image exactly like the C++ `ScenarioPolicy.g.h`.
pub struct ScenarioPolicy<'a> {
    pub tls_server_name: &'a str,
    pub http_path: &'a str,
    pub pinned_certificate_sha256: [u8; 32],
    pub max_response_bytes: usize,
}

/// Bounded, derived result. Mirrors the shape of the EDL `TlsSampleResult`.
#[derive(Debug, Clone, Copy)]
pub struct ServerAuthResult {
    pub status: ScenarioStatus,
    pub decision_allow: bool,
    pub output_value: u32,
    pub tls_version: u16,
    pub cipher_suite: u16,
    pub failure_reason: ScenarioStatus,
    pub clean_close: bool,
}

impl ServerAuthResult {
    fn failed(status: ScenarioStatus) -> Self {
        Self {
            status,
            decision_allow: false,
            output_value: 0,
            tls_version: 0,
            cipher_suite: 0,
            failure_reason: status,
            clean_close: false,
        }
    }
}

/// Transport error signalled by a [`TlsTransport`]. Deliberately opaque so the
/// derived result cannot leak host-side detail.
#[derive(Debug, Clone, Copy)]
pub struct TransportError;

/// Byte transport the driver uses to move TLS records. Implemented over a
/// socket in the host harness and over the `HostTcp*` EDL callbacks in the
/// enclave.
pub trait TlsTransport {
    /// Sends the whole slice (blocking / to completion).
    fn send(&mut self, data: &[u8]) -> Result<(), TransportError>;
    /// Reads up to `buf.len()` bytes. Returns the number read; `0` means the
    /// peer closed the TCP connection (no more bytes will arrive).
    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, TransportError>;
}

/// Fixed wall-clock time. The sample pins the exact leaf certificate and uses a
/// custom verifier that ignores time (matching the C++ sample, which compiles
/// mbedTLS time out entirely), and it uses no session tickets, so rustls needs
/// only a stable, non-monotonic time source — not a trusted clock.
#[derive(Debug)]
struct StubTimeProvider;

// 2025-01-01T00:00:00Z, comfortably inside the test certificate's validity.
const STUB_UNIX_SECONDS: u64 = 1_735_689_600;

impl TimeProvider for StubTimeProvider {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(Duration::from_secs(STUB_UNIX_SECONDS)))
    }
}

// Guards against a hostile or buggy peer trapping the driver in an unbounded
// I/O loop (mirrors the C++ driver's operation budget).
const MAX_TRANSPORT_OPERATIONS: u32 = 4096;
const INITIAL_INCOMING_CAPACITY: usize = 16 * 1024;

/// Runs the whole server-auth TLS 1.3 exchange to completion: handshake with a
/// pinned server certificate, issue one HTTP GET, read the bounded response,
/// then compute the derived result. Never returns transport bytes to the
/// caller — only the derived, bounded [`ServerAuthResult`].
pub fn run_server_auth_scenario(
    transport: &mut dyn TlsTransport,
    policy: &ScenarioPolicy<'_>,
    input_value: u32,
) -> ServerAuthResult {
    let server_name = match ServerName::try_from(policy.tls_server_name) {
        Ok(name) => name.to_owned(),
        Err(_) => return ServerAuthResult::failed(ScenarioStatus::InvalidState),
    };

    let verifier = Arc::new(PinnedServerVerifier::new(policy.pinned_certificate_sha256));
    let config = match ClientConfig::builder_with_details(
        Arc::new(provider_skeleton()),
        Arc::new(StubTimeProvider),
    )
    .with_protocol_versions(&[&TLS13])
    {
        Ok(builder) => builder
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth(),
        Err(_) => return ServerAuthResult::failed(ScenarioStatus::InvalidState),
    };

    let mut conn = match UnbufferedClientConnection::new(Arc::new(config), server_name) {
        Ok(conn) => conn,
        Err(_) => return ServerAuthResult::failed(ScenarioStatus::InvalidState),
    };

    let request = build_request(policy.tls_server_name, policy.http_path);

    let mut incoming: Vec<u8> = vec![0u8; INITIAL_INCOMING_CAPACITY];
    let mut incoming_used = 0usize;
    let mut outgoing: Vec<u8> = Vec::new();
    let mut body: Vec<u8> = Vec::new();

    let mut request_sent = false;
    let mut clean_close = false;
    let mut operations: u32 = 0;

    loop {
        if operations >= MAX_TRANSPORT_OPERATIONS {
            return ServerAuthResult::failed(ScenarioStatus::ProtocolFailed);
        }

        let UnbufferedStatus { mut discard, state } =
            conn.process_tls_records(&mut incoming[..incoming_used]);

        let state = match state {
            Ok(state) => state,
            Err(_) => return ServerAuthResult::failed(ScenarioStatus::ProtocolFailed),
        };

        let mut need_recv = false;
        let mut stop = false;

        match state {
            ConnectionState::EncodeTlsData(mut encoder) => {
                if drain_encode(&mut encoder, &mut outgoing).is_err() {
                    return ServerAuthResult::failed(ScenarioStatus::ProtocolFailed);
                }
            }
            ConnectionState::TransmitTlsData(transmit) => {
                if !outgoing.is_empty() {
                    if transport.send(&outgoing).is_err() {
                        return ServerAuthResult::failed(ScenarioStatus::TransportFailed);
                    }
                    outgoing.clear();
                    operations += 1;
                }
                transmit.done();
            }
            ConnectionState::BlockedHandshake => {
                need_recv = true;
            }
            ConnectionState::WriteTraffic(mut writer) => {
                if !request_sent {
                    match writer.encrypt(&request, spare(&mut outgoing, request.len() + 256)) {
                        Ok(written) => {
                            outgoing.truncate(written);
                            if transport.send(&outgoing).is_err() {
                                return ServerAuthResult::failed(ScenarioStatus::TransportFailed);
                            }
                            outgoing.clear();
                            operations += 1;
                            request_sent = true;
                        }
                        Err(_) => return ServerAuthResult::failed(ScenarioStatus::ProtocolFailed),
                    }
                } else {
                    // Request already sent; pull the response.
                    need_recv = true;
                }
            }
            ConnectionState::ReadTraffic(mut reader) => {
                while let Some(record) = reader.next_record() {
                    let AppDataRecord {
                        discard: d,
                        payload,
                    } = match record {
                        Ok(record) => record,
                        Err(_) => return ServerAuthResult::failed(ScenarioStatus::ProtocolFailed),
                    };
                    discard += d;
                    if body.len() + payload.len() > policy.max_response_bytes {
                        return ServerAuthResult::failed(ScenarioStatus::Truncated);
                    }
                    body.extend_from_slice(payload);
                }
            }
            ConnectionState::PeerClosed => {
                clean_close = true;
                stop = true;
            }
            ConnectionState::Closed => {
                stop = true;
            }
            _ => {}
        }

        if discard > 0 {
            incoming.copy_within(discard..incoming_used, 0);
            incoming_used -= discard;
        }

        if stop {
            break;
        }

        if need_recv {
            if incoming_used == incoming.len() {
                incoming.resize(incoming.len() * 2, 0);
            }
            match transport.recv(&mut incoming[incoming_used..]) {
                Ok(0) => {
                    // TCP EOF. Clean only if we already saw close_notify.
                    break;
                }
                Ok(n) => {
                    incoming_used += n;
                    operations += 1;
                }
                Err(_) => return ServerAuthResult::failed(ScenarioStatus::TransportFailed),
            }
        }
    }

    if !request_sent {
        return ServerAuthResult::failed(ScenarioStatus::ProtocolFailed);
    }

    let tls_version = conn.protocol_version().map(u16::from).unwrap_or(0);
    let cipher_suite = conn
        .negotiated_cipher_suite()
        .map(|s| u16::from(s.suite()))
        .unwrap_or(0);

    let status = if clean_close {
        ScenarioStatus::Ok
    } else {
        // The peer closed the TCP connection without a TLS close_notify: the
        // response may be truncated, so it is not trusted.
        ScenarioStatus::Truncated
    };

    if status != ScenarioStatus::Ok {
        return ServerAuthResult {
            status,
            decision_allow: false,
            output_value: 0,
            tls_version,
            cipher_suite,
            failure_reason: status,
            clean_close,
        };
    }

    let response = match core::str::from_utf8(&body) {
        Ok(text) => text,
        Err(_) => {
            return ServerAuthResult {
                status: ScenarioStatus::ValidationFailed,
                decision_allow: false,
                output_value: 0,
                tls_version,
                cipher_suite,
                failure_reason: ScenarioStatus::ValidationFailed,
                clean_close,
            }
        }
    };

    let Some(multiplier) = extract_multiplier(response) else {
        return ServerAuthResult {
            status: ScenarioStatus::ValidationFailed,
            decision_allow: false,
            output_value: 0,
            tls_version,
            cipher_suite,
            failure_reason: ScenarioStatus::ValidationFailed,
            clean_close,
        };
    };

    // Derived-result contract: the server payload materially affects behaviour,
    // but only a bounded, derived value leaves the enclave.
    ServerAuthResult {
        status: ScenarioStatus::Ok,
        decision_allow: (input_value & 1) == 0,
        output_value: input_value.wrapping_mul(multiplier),
        tls_version,
        cipher_suite,
        failure_reason: ScenarioStatus::Ok,
        clean_close,
    }
}

fn build_request(host: &str, path: &str) -> Vec<u8> {
    let mut request = Vec::new();
    request.extend_from_slice(b"GET ");
    request.extend_from_slice(path.as_bytes());
    request.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(b"\r\nConnection: close\r\n\r\n");
    request
}

/// Grows `buf` to at least `needed` bytes of zeroed scratch and returns it as a
/// mutable slice for one-shot encode/encrypt calls.
fn spare(buf: &mut Vec<u8>, needed: usize) -> &mut [u8] {
    buf.clear();
    buf.resize(needed, 0);
    &mut buf[..]
}

/// Encodes handshake TLS data, growing the scratch buffer until it fits, and
/// appends the encoded bytes to `outgoing`.
fn drain_encode(
    encoder: &mut rustls::unbuffered::EncodeTlsData<'_, rustls::client::ClientConnectionData>,
    outgoing: &mut Vec<u8>,
) -> Result<(), ()> {
    let mut scratch = vec![0u8; 4096];
    loop {
        match encoder.encode(&mut scratch) {
            Ok(written) => {
                outgoing.extend_from_slice(&scratch[..written]);
                return Ok(());
            }
            Err(EncodeError::InsufficientSize(needed)) => {
                scratch = vec![0u8; needed.required_size];
            }
            Err(_) => return Err(()),
        }
    }
}

fn extract_multiplier(response: &str) -> Option<u32> {
    let marker = "\"multiplier\":";
    let start = response.find(marker)? + marker.len();
    let digits: Vec<u8> = response[start..]
        .bytes()
        .skip_while(|b| *b == b' ')
        .take_while(|b| b.is_ascii_digit())
        .collect();
    if digits.is_empty() {
        return None;
    }
    let text = core::str::from_utf8(&digits).ok()?;
    text.parse().ok()
}
