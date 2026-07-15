// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! VTL0 host for the Rust TLS enclave sample. Loads the enclave, registers the
//! VTL0 transport callbacks, then asks the enclave to run a scenario and prints
//! the bounded, derived result. The host supplies only transport; the enclave
//! owns all server-identity policy.

mod edl_impls;

use crate::edl_impls::HostImpl;
use tls_sample_host_gen::implementation::types::*;
use tls_sample_host_gen::stubs::trusted::TlsSampleHost;
use vbsenclave_sdk_host::enclave::{self, EnclaveHandle};

const ENCLAVE_CREATE_INFO_FLAG: u32 = {
    #[cfg(debug_assertions)]
    {
        enclave::ENCLAVE_CREATE_INFO_FLAG_DEBUG
    }

    #[cfg(not(debug_assertions))]
    {
        enclave::ENCLAVE_CREATE_INFO_FLAG_RELEASE
    }
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let enclave_path = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| String::from("tls_sample_enclave.dll"));
    let scenario_id: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
    let input_value: u32 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(38);

    let enclave_handle = EnclaveHandle::create_and_initialize(
        &enclave_path,
        enclave::megabytes(256),
        None,
        ENCLAVE_CREATE_INFO_FLAG,
    )?;

    let host = TlsSampleHost::new(enclave_handle.as_ptr());

    if let Err(err) = host.register_vtl0_callbacks::<HostImpl>() {
        return Err(format!(
            "Failed to register VTL0 callbacks: HRESULT {:x}",
            err.to_hresult().0
        )
        .into());
    }
    if let Err(err) = vbsenclave_sdk_host::register_sdk_callbacks(enclave_handle.as_ptr()) {
        return Err(format!(
            "Failed to register SDK VTL0 callbacks: HRESULT {:x}",
            err.to_hresult().0
        )
        .into());
    }

    // The enclave owns the policy; the host can display it but not change it.
    // The enclave owns the policy; the host can display it but not change it.
    let mut metadata = TlsSampleScenarioMetadata::default();
    if let Err(err) = host.TlsSample_GetScenarioMetadata(scenario_id, &mut metadata) {
        return Err(format!(
            "TlsSample_GetScenarioMetadata failed: HRESULT {:x}",
            err.to_hresult().0
        )
        .into());
    }
    if metadata.status != TlsSampleStatus::TlsSampleStatus_Ok {
        return Err(format!("unknown scenario {scenario_id}").into());
    }

    println!("scenario_id={}", metadata.scenario_id);
    println!("connect={}:{}", metadata.connect_host, metadata.connect_port);
    println!("tls_server_name={}", metadata.tls_server_name);
    println!("http_path={}", metadata.http_path);

    let request = TlsSampleRequest {
        scenario_id,
        input_value,
    };
    let mut result = TlsSampleResult::default();
    if let Err(err) = host.TlsSample_RunScenario(&request, &mut result) {
        return Err(format!(
            "TlsSample_RunScenario failed: HRESULT {:x}",
            err.to_hresult().0
        )
        .into());
    }

    println!("status={}", result.status as u32);
    println!(
        "decision={}",
        if result.decision == TlsSampleDecision::TlsSampleDecision_Allow {
            "Allow"
        } else {
            "Deny"
        }
    );
    println!("output_value={}", result.output_value);
    println!("failure_reason={}", result.failure_reason as u32);
    println!("tls_version=0x{:x}", result.tls_version);
    println!("cipher_suite=0x{:x}", result.cipher_suite);

    if result.status == TlsSampleStatus::TlsSampleStatus_Ok {
        Ok(())
    } else {
        Err(format!("scenario failed with status {}", result.status as u32).into())
    }
}
