// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Verifies the pinned-certificate trust anchor: a certificate whose SHA-256
// does not match the pin is rejected before any name/parse work. The positive
// path (matching pin + hostname/SAN) and the hostname-mismatch rejection are
// covered end-to-end by Test-RustlsHostHarness.ps1 against the real test
// certificate, which is generated at test time.

use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls_feasibility::bcrypt_provider::PinnedServerVerifier;

#[test]
fn rejects_certificate_with_wrong_pin() {
    // Any bytes: the pin check runs first and fails, so the input need not be a
    // well-formed certificate.
    let not_the_pinned_cert = CertificateDer::from(vec![0x30, 0x00, 0x01, 0x02, 0x03]);
    let verifier = PinnedServerVerifier::new([0xAB; 32]);
    let server_name = ServerName::try_from("localhost").unwrap();

    let result = verifier.verify_server_cert(
        &not_the_pinned_cert,
        &[],
        &server_name,
        &[],
        UnixTime::since_unix_epoch(core::time::Duration::from_secs(1_735_689_600)),
    );

    assert!(
        result.is_err(),
        "a certificate that does not match the pin must be rejected"
    );
}
