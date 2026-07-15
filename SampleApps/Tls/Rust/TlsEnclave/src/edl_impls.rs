// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Enclave-side (VTL1) implementation of the trusted EDL surface.
//!
//! `TlsSample_RunScenario` runs the whole server-auth TLS 1.3 exchange to
//! completion inside the enclave via the shared `tls_driver`, driving transport
//! through the generated `HostTcp*` callbacks into VTL0. VTL0 supplies only
//! sockets; all server-identity policy (endpoint, SNI, path, certificate pin,
//! limits) is baked into the image (`scenario_policy.g.rs`).

extern crate alloc;

use core::sync::atomic::{AtomicBool, Ordering};

use rustls_feasibility::tls_driver::{
    run_server_auth_scenario, ScenarioPolicy, ScenarioStatus, TlsTransport, TransportError,
};

use tls_sample_enclave_gen::implementation::trusted::Trusted;
use tls_sample_enclave_gen::implementation::types::*;
use tls_sample_enclave_gen::stubs::untrusted;
use tls_sample_enclave_gen::AbiError;

// Enclave-owned scenario policy pinned into the image at build time.
mod policy {
    include!("scenario_policy.g.rs");
}

const MAX_RESPONSE_BYTES: usize = 16 * 1024;

pub struct EnclaveImpl;

/// Serialises the enclave to a single active TLS session and rejects nested or
/// concurrent entry (mirrors the C++ sample's admission guard). It must not
/// spin: the run holds it across outbound transport callbacks.
static RUNNING: AtomicBool = AtomicBool::new(false);

struct RunGuard;

impl Drop for RunGuard {
    fn drop(&mut self) {
        RUNNING.store(false, Ordering::Release);
    }
}

/// Moves TLS records through the generated `HostTcp*` callbacks into VTL0.
struct EnclaveTransport {
    handle: u64,
}

impl TlsTransport for EnclaveTransport {
    fn send(&mut self, data: &[u8]) -> Result<(), TransportError> {
        let result =
            untrusted::TlsSample_HostTcpSend(self.handle, data).map_err(|_| TransportError)?;
        match result.status {
            HostIoStatus::HostIoStatus_Ok => Ok(()),
            _ => Err(TransportError),
        }
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, TransportError> {
        let result = untrusted::TlsSample_HostTcpRecv(self.handle, buf.len() as u32)
            .map_err(|_| TransportError)?;
        match result.status {
            HostIoStatus::HostIoStatus_Ok => {
                // The enclave requested at most buf.len() bytes; reject a host
                // that returns more than it was asked for.
                if result.bytes.len() > buf.len() {
                    return Err(TransportError);
                }
                let n = result.bytes.len();
                buf[..n].copy_from_slice(&result.bytes);
                Ok(n)
            }
            HostIoStatus::HostIoStatus_Closed => Ok(0),
            _ => Err(TransportError),
        }
    }
}

fn to_abi_status(status: ScenarioStatus) -> TlsSampleStatus {
    match status {
        ScenarioStatus::Ok => TlsSampleStatus::TlsSampleStatus_Ok,
        ScenarioStatus::Closed => TlsSampleStatus::TlsSampleStatus_Closed,
        ScenarioStatus::Truncated => TlsSampleStatus::TlsSampleStatus_Truncated,
        ScenarioStatus::ValidationFailed => TlsSampleStatus::TlsSampleStatus_ValidationFailed,
        ScenarioStatus::TransportFailed => TlsSampleStatus::TlsSampleStatus_TransportFailed,
        ScenarioStatus::ProtocolFailed => TlsSampleStatus::TlsSampleStatus_ProtocolFailed,
        ScenarioStatus::InvalidState => TlsSampleStatus::TlsSampleStatus_InvalidState,
    }
}

impl Trusted for EnclaveImpl {
    fn TlsSample_GetScenarioMetadata(
        scenario_id: u32,
        metadata: &mut TlsSampleScenarioMetadata,
    ) -> Result<i32, AbiError> {
        *metadata = TlsSampleScenarioMetadata::default();
        metadata.scenario_id = scenario_id;

        if scenario_id != 0 {
            metadata.status = TlsSampleStatus::TlsSampleStatus_UnknownScenario;
            return Ok(0);
        }

        metadata.status = TlsSampleStatus::TlsSampleStatus_Ok;
        metadata.profile = TlsSampleProfile::TlsSampleProfile_ServerAuth;
        metadata.connect_host = policy::SCENARIO0_CONNECT_HOST.into();
        metadata.connect_port = policy::SCENARIO0_CONNECT_PORT;
        metadata.tls_server_name = policy::SCENARIO0_TLS_SERVER_NAME.into();
        metadata.http_path = policy::SCENARIO0_HTTP_PATH.into();
        metadata.max_response_bytes = MAX_RESPONSE_BYTES as u32;
        metadata.pinned_certificate_sha256 = policy::SCENARIO0_CERTIFICATE_SHA256;
        Ok(0)
    }

    fn TlsSample_RunScenario(
        request: &TlsSampleRequest,
        result: &mut TlsSampleResult,
    ) -> Result<i32, AbiError> {
        *result = TlsSampleResult::default();
        result.status = TlsSampleStatus::TlsSampleStatus_InvalidState;
        result.failure_reason = TlsSampleStatus::TlsSampleStatus_InvalidState;

        if request.scenario_id != 0 {
            result.status = TlsSampleStatus::TlsSampleStatus_UnknownScenario;
            result.failure_reason = TlsSampleStatus::TlsSampleStatus_UnknownScenario;
            return Ok(0);
        }

        // Reject concurrent or re-entrant runs.
        if RUNNING.swap(true, Ordering::Acquire) {
            result.status = TlsSampleStatus::TlsSampleStatus_AccessDenied;
            result.failure_reason = TlsSampleStatus::TlsSampleStatus_AccessDenied;
            return Ok(0);
        }
        let _guard = RunGuard;

        let connect =
            match untrusted::TlsSample_HostTcpConnect(policy::SCENARIO0_CONNECT_HOST, policy::SCENARIO0_CONNECT_PORT) {
                Ok(connect) => connect,
                Err(_) => {
                    result.status = TlsSampleStatus::TlsSampleStatus_TransportFailed;
                    result.failure_reason = TlsSampleStatus::TlsSampleStatus_TransportFailed;
                    return Ok(0);
                }
            };

        if connect.status != HostIoStatus::HostIoStatus_Ok {
            result.status = TlsSampleStatus::TlsSampleStatus_TransportFailed;
            result.failure_reason = TlsSampleStatus::TlsSampleStatus_TransportFailed;
            return Ok(0);
        }

        let mut transport = EnclaveTransport {
            handle: connect.transport_handle,
        };
        let driver_policy = ScenarioPolicy {
            tls_server_name: policy::SCENARIO0_TLS_SERVER_NAME,
            http_path: policy::SCENARIO0_HTTP_PATH,
            pinned_certificate_sha256: policy::SCENARIO0_CERTIFICATE_SHA256,
            max_response_bytes: MAX_RESPONSE_BYTES,
        };

        let outcome = run_server_auth_scenario(&mut transport, &driver_policy, request.input_value);

        let _ = untrusted::TlsSample_HostTcpClose(connect.transport_handle);

        result.status = to_abi_status(outcome.status);
        result.decision = if outcome.decision_allow {
            TlsSampleDecision::TlsSampleDecision_Allow
        } else {
            TlsSampleDecision::TlsSampleDecision_Deny
        };
        result.output_value = outcome.output_value;
        result.tls_version = outcome.tls_version as u32;
        result.cipher_suite = outcome.cipher_suite;
        result.failure_reason = to_abi_status(outcome.failure_reason);
        Ok(0)
    }
}
