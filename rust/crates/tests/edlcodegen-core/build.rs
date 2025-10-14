// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use edlcodegen_tools::flatc_path;
use std::{env, path::PathBuf, process::Command};

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let schema_path = manifest_dir.join("tests\\flatbuffer_test_schema.fbs");
    assert!(
        schema_path.exists(),
        "Missing flatbuffer schema file: {}",
        schema_path.display()
    );
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let gen_out_path = format!("{out_dir}/flatbuffer_gen");

    // Tell Cargo to rebuild if we change our test .fbs file.
    println!("cargo:rerun-if-changed={}", schema_path.to_str().unwrap());

    let status = Command::new(flatc_path())
        .current_dir(&manifest_dir)
        .args([
            "--rust",
            "--gen-object-api",
            "--force-empty",
            "--no-prefix",
            "--rust-module-root-file",
            "--gen-all",
            "--filename-suffix",
            "", // So --filename-suffix takes empty string as suffix
            "-o",
            &gen_out_path,
            schema_path.to_str().unwrap(),
        ])
        .status()
        .expect("failed to run flatc");

    assert!(status.success(), "flatc failed with status {}", status);
}
