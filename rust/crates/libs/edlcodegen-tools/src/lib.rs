// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::{env, path::PathBuf};

/// Returns the folder path where the tools were installed.
fn tool_root() -> PathBuf {
    PathBuf::from(env!("EDLCODEGEN_TOOL_PATH"))
}

/// Returns the full path to `edlcodegen.exe`.
pub fn edlcodegen_path() -> PathBuf {
    tool_root().join("bin/edlcodegen.exe")
}

/// Returns the full path to `flatc.exe`.
pub fn flatc_path() -> PathBuf {
    tool_root().join("vcpkg/tools/flatbuffers/flatc.exe")
}
