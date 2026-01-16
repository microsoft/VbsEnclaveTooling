// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use windows_bindgen::bindgen;

const KEY_CREDENTIAL_MANAGER_FILENAME: &str = "bindings.rs";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Only rerun if the build.rs file changes so that we don't regenerate unnecessarily.
    println!("cargo:rerun-if-changed=build.rs");
    let cur_dir = std::env::var("CARGO_MANIFEST_DIR")?;
    let bindings_out_path = format!("{}/src/{}", cur_dir, KEY_CREDENTIAL_MANAGER_FILENAME);

    let windows_winmd = format!("{}/winmds", cur_dir);

    let args = [
        "--in",
        "default",
        &windows_winmd,
        "--out",
        &bindings_out_path,
        "--flat",
        "--implement",
        "--filter",
        "Windows.Foundation.TimeSpan",
        "Windows.Security.Credentials.AttestationChallengeHandler",
        "Windows.Security.Credentials.ChallengeResponseKind",
        "Windows.Security.Credentials.IKeyCredential",
        "Windows.Security.Credentials.IKeyCredential2",
        "Windows.Security.Credentials.IKeyCredentialAttestationResult",
        "Windows.Security.Credentials.IKeyCredentialCacheConfiguration",
        "Windows.Security.Credentials.IKeyCredentialCacheConfigurationFactory",
        "Windows.Security.Credentials.IKeyCredentialOperationResult",
        "Windows.Security.Credentials.IKeyCredentialManagerStatics2",
        "Windows.Security.Credentials.IKeyCredentialRetrievalResult",
        "Windows.Security.Credentials.KeyCredential",
        "Windows.Security.Credentials.KeyCredentialAttestationResult",
        "Windows.Security.Credentials.KeyCredentialAttestationStatus",
        "Windows.Security.Credentials.KeyCredentialCacheConfiguration",
        "Windows.Security.Credentials.KeyCredentialCacheOption",
        "Windows.Security.Credentials.KeyCredentialCreationOption",
        "Windows.Security.Credentials.KeyCredentialManager",
        "Windows.Security.Credentials.KeyCredentialOperationResult",
        "Windows.Security.Credentials.KeyCredentialRetrievalResult",
        "Windows.Security.Credentials.KeyCredentialStatus",
        "Windows.Security.Cryptography.Core.CryptographicPublicKeyBlobType",
        "Windows.Storage.Streams.IBuffer",
        "Windows.UI.WindowId",
    ];

    // Generate the bindings for bindings.rs from Windows.winmd
    bindgen(args).unwrap();
    Ok(())
}
