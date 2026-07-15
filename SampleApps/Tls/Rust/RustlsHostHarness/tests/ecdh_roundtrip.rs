// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Regression guard for the BCrypt ECDH byte-order fix. BCRYPT_KDF_RAW_SECRET
// returns the shared secret little-endian; TLS uses the big-endian X coordinate.
// A round-trip must agree on both sides and yield a full-width secret. The
// end-to-end handshake test (Test-RustlsHostHarness.ps1) additionally proves
// interop against a standard TLS stack, which catches a both-sides-reversed
// error that a pure round-trip cannot.

use rustls::crypto::SupportedKxGroup;
use rustls_feasibility::bcrypt_provider::{P256, P384};

fn roundtrip(group: &'static dyn SupportedKxGroup, coordinate_len: usize) {
    let alice = group.start().expect("alice start");
    let bob = group.start().expect("bob start");

    let alice_pub = alice.pub_key().to_vec();
    let bob_pub = bob.pub_key().to_vec();

    let alice_secret = alice.complete(&bob_pub).expect("alice complete");
    let bob_secret = bob.complete(&alice_pub).expect("bob complete");

    assert_eq!(
        alice_secret.secret_bytes(),
        bob_secret.secret_bytes(),
        "both peers must derive the same ECDH shared secret"
    );
    assert_eq!(
        alice_secret.secret_bytes().len(),
        coordinate_len,
        "shared secret must be the full big-endian coordinate width"
    );
}

#[test]
fn p256_ecdh_roundtrip_agrees() {
    roundtrip(&P256, 32);
}

#[test]
fn p384_ecdh_roundtrip_agrees() {
    roundtrip(&P384, 48);
}
