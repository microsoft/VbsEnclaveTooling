// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::path::PathBuf;

pub fn exes_path() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir).join("exes/")
}
/// Returns the full path to `edlcodegen.exe`.
pub fn edlcodegen_path() -> PathBuf {
    exes_path().join("edlcodegen/edlcodegen.exe")
}

/// Returns the full path to `flatc.exe`.
pub fn flatc_path() -> PathBuf {
    exes_path().join("flatbuffers/flatc.exe")
}
