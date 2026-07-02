// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::Arc;

use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::hash::Hash;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, StreamOwned};
use rustls_feasibility::bcrypt_provider::{provider_skeleton, PinnedServerVerifier, SHA256};

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

    let cert = read_first_certificate(&cert_path)?;
    let mut pin = [0u8; 32];
    pin.copy_from_slice(SHA256.hash(cert.as_ref()).as_ref());

    let provider = provider_skeleton();
    let verifier: Arc<dyn ServerCertVerifier> = Arc::new(PinnedServerVerifier::new(pin));
    let config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    let server_name = ServerName::try_from("localhost")?.to_owned();
    let connection = ClientConnection::new(Arc::new(config), server_name)?;
    let socket = TcpStream::connect(("127.0.0.1", port))?;
    let mut stream = StreamOwned::new(connection, socket);

    let request = b"GET /secret-config HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    stream.write_all(request)?;
    stream.flush()?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let multiplier = extract_multiplier(&response).ok_or("missing multiplier")?;

    println!("pinned_cert_sha256={}", hex(&pin));
    println!("status=0");
    println!(
        "decision={}",
        if input_value % 2 == 0 { "Allow" } else { "Deny" }
    );
    println!("output_value={}", input_value * multiplier);
    println!(
        "diagnostics={:?}, {:?}, server-auth-ok",
        stream.conn.protocol_version(),
        stream.conn.negotiated_cipher_suite().map(|suite| suite.suite())
    );

    Ok(())
}

fn read_first_certificate(path: &PathBuf) -> Result<CertificateDer<'static>, Box<dyn std::error::Error>> {
    let mut reader = BufReader::new(File::open(path)?);
    rustls_pemfile::certs(&mut reader)
        .next()
        .ok_or_else(|| -> Box<dyn std::error::Error> { "no certificate in PEM".into() })?
        .map_err(Into::into)
}

fn extract_multiplier(response: &str) -> Option<u32> {
    let marker = "\"multiplier\":";
    let start = response.find(marker)? + marker.len();
    let digits = response[start..]
        .trim_start()
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .collect::<String>();
    digits.parse().ok()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
