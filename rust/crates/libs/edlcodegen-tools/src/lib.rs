// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::env;
use std::path::PathBuf;
use std::process::Command;
use std::str;
use winreg::RegKey;

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

const PROGRAM_FILES_X86: &str = "ProgramFiles(x86)";
const DEFAULT_VCTOOLS_VERSION_FILE_PATH: &str =
    "VC\\Auxiliary\\Build\\Microsoft.VCToolsVersion.default.txt";
const MSVC_PATH: &str = "VC\\Tools\\MSVC";
const VC_TOOLS_X64: &str = "Microsoft.VisualStudio.Component.VC.Tools.x86.x64";
const ENCLAVE_LIB_X64_PATH: &str = "lib\\x64\\enclave";
const UCRT_LIB_X64_PATH: &str = "ucrt_enclave\\x64\\ucrt.lib";

const VC_TOOLS_ARM64: &str = "Microsoft.VisualStudio.Component.VC.Tools.ARM64";
const ENCLAVE_LIB_ARM64_PATH: &str = "lib\\arm64\\enclave";
const UCRT_LIB_ARM64_PATH: &str = "ucrt_enclave\\arm64\\ucrt.lib";

fn get_architecture_sub_paths() -> (&'static str, &'static str, &'static str) {
    match env::consts::ARCH {
        "x86_64" => (VC_TOOLS_X64, ENCLAVE_LIB_X64_PATH, UCRT_LIB_X64_PATH),
        "aarch64" => (VC_TOOLS_ARM64, ENCLAVE_LIB_ARM64_PATH, UCRT_LIB_ARM64_PATH),
        _ => panic!("Unsupported architecture: {}", env::consts::ARCH),
    }
}

fn get_sdk_lib_path() -> Result<String, Box<dyn std::error::Error>> {
    let hklm = RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE);
    let root = hklm.open_subkey(r"SOFTWARE\Wow6432Node\Microsoft\Windows Kits\Installed Roots")?;

    let kits_root_10: String = root.get_value("KitsRoot10")?;

    // Pick newest installed Windows SDK version.
    // E.g HLKM\SOFTWARE\Wow6432Node\Microsoft\Windows Kits\Installed Roots\10.0.22000.0
    let newest_version = root
        .enum_keys()
        .flatten()
        .filter(|k| k.chars().next().is_some_and(|c| c.is_ascii_digit())) // only version keys
        .max()
        .ok_or("No Windows SDK version keys found")?;

    Ok(format!("{}/Lib/{}", kits_root_10, newest_version))
}

fn find_latest_msvc_install(vc_tools: &str) -> Result<String, Box<dyn std::error::Error>> {
    let program_files_x86 = env::var(PROGRAM_FILES_X86)
        .map_err(|_| "ProgramFiles(x86) environment variable not set")?;

    let vswhere = format!("{program_files_x86}\\Microsoft Visual Studio\\Installer\\vswhere.exe");

    // Run vswhere
    let output = Command::new(vswhere)
        .args([
            "-latest",
            "-products",
            "*",
            "-requires",
            vc_tools,
            "-property",
            "installationPath",
        ])
        .output()?
        .stdout;

    // Convert output to a cleaned-up string
    let install_path = String::from_utf8(output)?.trim().to_owned();

    Ok(install_path)
}

/// Emits the linker arguments needed to build this crate as a VBS enclave.
/// See: https://learn.microsoft.com/windows/win32/trusted-execution/vbs-enclaves-dev-guide
/// This function should be called from the build.rs file of an enclave crate.
pub fn set_enclave_linker_flags() {
    println!("cargo::rustc-link-arg=/ENCLAVE");
    println!("cargo::rustc-link-arg=/NODEFAULTLIB");
    println!("cargo::rustc-link-arg=/INCREMENTAL:NO");
    println!("cargo::rustc-link-arg=/INTEGRITYCHECK");
    println!("cargo::rustc-link-arg=/GUARD:MIXED");
}

/// Locates the Windows SDK and MSVC toolchain and links the the libraries
/// necessary to build a vbs enclave as outlined by the devellopment guide.
/// See: https://learn.microsoft.com/windows/win32/trusted-execution/vbs-enclaves-dev-guide
/// This function should be called from the build.rs file of an enclave crate.
pub fn link_win_sdk_enclave_libs() -> Result<(), Box<dyn std::error::Error>> {
    let sdk_path = get_sdk_lib_path()?;
    let (vc_tools, enclave_lib_sub_path, ucrt_lib_sub_path) = get_architecture_sub_paths();
    let install_path = find_latest_msvc_install(vc_tools)?;

    // Read VCToolsVersion.default.txt to get the default MSVC version subpath
    let vc_tool_file = format!("{install_path}/{DEFAULT_VCTOOLS_VERSION_FILE_PATH}");
    let vc_tool_version = std::fs::read_to_string(vc_tool_file)?;

    // link libraries
    println!("cargo::rustc-link-arg=vertdll.lib");
    println!("cargo::rustc-link-arg=bcrypt.lib");

    let ucrt_lib_path = format!("{}/{}", sdk_path, ucrt_lib_sub_path);
    println!("cargo::rustc-link-arg={}", ucrt_lib_path);

    let full_msvc_path = format!("{}/{}/{}", install_path, MSVC_PATH, vc_tool_version.trim());
    let msvc_with_enclave_lib_path = format!("{}/{}", full_msvc_path, enclave_lib_sub_path);

    let libvcruntime_path = format!("{}/libvcruntime.lib", msvc_with_enclave_lib_path);
    println!("cargo::rustc-link-arg={}", libvcruntime_path);

    let libcmt_path = format!("{}/libcmt.lib", msvc_with_enclave_lib_path);
    println!("cargo::rustc-link-arg={}", libcmt_path);

    Ok(())
}
