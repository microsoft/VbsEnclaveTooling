// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-mode harness that exercises the shared `no_std` TLS driver
//! (`rustls_feasibility::tls_driver`) against the local TLS 1.3 test server.
//!
//! The harness runs in `std` and moves TLS records over a real socket, but it
//! drives the *same* unbuffered driver that the VTL1 enclave will run. Only the
//! [`TlsTransport`] implementation differs between here and the enclave, so a
//! green run here proves the enclave's TLS logic before the EDL/enclave wiring
//! is added.

use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;

use rustls::crypto::hash::Hash;
use rustls::pki_types::CertificateDer;
use rustls_feasibility::bcrypt_provider::SHA256;
use rustls_feasibility::tls_driver::{
    run_server_auth_scenario, ScenarioPolicy, ScenarioStatus, TlsTransport, TransportError,
};

/// Moves TLS records over a blocking TCP socket. The enclave will provide the
/// equivalent over the generated `HostTcp*` EDL callbacks instead.
struct SocketTransport {
    stream: TcpStream,
}

impl TlsTransport for SocketTransport {
    fn send(&mut self, data: &[u8]) -> Result<(), TransportError> {
        self.stream.write_all(data).map_err(|_| TransportError)
    }

    fn recv(&mut self, buf: &mut [u8]) -> Result<usize, TransportError> {
        self.stream.read(buf).map_err(|_| TransportError)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let cert_path = PathBuf::from(args.next().unwrap_or_else(|| {
        String::from("SampleApps\\Tls\\TestServer\\test-certs\\server-cert.pem")
    }));
    let port: u16 = args
        .next()
        .unwrap_or_else(|| String::from("9781"))
        .parse()?;
    let input_value: u32 = args.next().unwrap_or_else(|| String::from("38")).parse()?;
    // Optional SNI/hostname override, so a wrong-name run can exercise the
    // hostname/SAN rejection path. Defaults to the pinned server's name.
    let server_name = args.next().unwrap_or_else(|| String::from("localhost"));

    let cert = read_first_certificate(&cert_path)?;
    let mut pin = [0u8; 32];
    pin.copy_from_slice(SHA256.hash(cert.as_ref()).as_ref());

    let policy = ScenarioPolicy {
        tls_server_name: &server_name,
        http_path: "/secret-config",
        pinned_certificate_sha256: pin,
        max_response_bytes: 16 * 1024,
    };

    let mut transport = SocketTransport {
        stream: TcpStream::connect(("127.0.0.1", port))?,
    };

    let result = run_server_auth_scenario(&mut transport, &policy, input_value);

    println!("pinned_cert_sha256={}", hex(&pin));
    println!("status={}", result.status as u32);
    println!(
        "decision={}",
        if result.decision_allow { "Allow" } else { "Deny" }
    );
    println!("output_value={}", result.output_value);
    println!("failure_reason={}", result.failure_reason as u32);
    println!("tls_version=0x{:x}", result.tls_version);
    println!("cipher_suite=0x{:x}", result.cipher_suite);

    if result.status == ScenarioStatus::Ok {
        Ok(())
    } else {
        Err(format!("scenario failed with status {}", result.status as u32).into())
    }
}

fn read_first_certificate(
    path: &PathBuf,
) -> Result<CertificateDer<'static>, Box<dyn std::error::Error>> {
    let mut reader = BufReader::new(File::open(path)?);
    rustls_pemfile::certs(&mut reader)
        .next()
        .ok_or_else(|| -> Box<dyn std::error::Error> { "no certificate in PEM".into() })?
        .map_err(Into::into)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
