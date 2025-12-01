// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::env;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::str;

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
const VCTOOLS_DEFAULT_PATH: &str = "VC\\Auxiliary\\Build\\Microsoft.VCToolsVersion.default.txt";
const MSVC_PATH: &str = "VC\\Tools\\MSVC";
const ENCLAVE_LIB_PATH: &str = "lib\\x64\\enclave";
const UCRT_LIB_PATH: &str = "ucrt_enclave\\x64\\ucrt.lib";

const SDK_SCRIPT: &str = r#"& {
    $kits_root_10 = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows Kits\Installed Roots\" -Name KitsRoot10).KitsRoot10
    $sdk_version = (Get-ChildItem -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows Kits\Installed Roots\" | Sort-Object -Descending)[0] | Split-Path -Leaf
    Write-Host "$($kits_root_10)Lib\$sdk_version"
}
"#;

/// Locates the Windows SDK and MSVC toolchain and emits the linker arguments
/// needed to build a VBS enclave (UCRT enclave libs + MSVC enclave libs + vertdll).
pub fn link_win_sdk_enclave_libs() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo::rustc-link-arg=/ENCLAVE");
    println!("cargo::rustc-link-arg=/NODEFAULTLIB");
    println!("cargo::rustc-link-arg=/INCREMENTAL:NO");
    println!("cargo::rustc-link-arg=/INTEGRITYCHECK");
    println!("cargo::rustc-link-arg=/GUARD:MIXED");

    let program_files_x86 =
        env::var(PROGRAM_FILES_X86).expect("Program Files (x86) path not in environment variables");

    let powershell_output = Command::new("powershell.exe")
        .arg(SDK_SCRIPT)
        .output()?
        .stdout;
    let sdk_path = str::from_utf8(&powershell_output)?.trim();

    println!("{}", sdk_path);

    let vswhere =
        Path::new(&program_files_x86).join("Microsoft Visual Studio\\Installer\\vswhere.exe");

    let vswhere_output = Command::new(vswhere)
        .args([
            "-latest",
            "-products",
            "*",
            "-requires",
            "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
            "-property",
            "installationPath",
        ])
        .output()?
        .stdout;

    let install_path = Path::new(str::from_utf8(&vswhere_output)?.trim());

    let mut default_path = String::new();
    std::fs::File::open(install_path.join(VCTOOLS_DEFAULT_PATH))
        .expect("Could not open Microsoft.VCToolsVersion.default.txt")
        .read_to_string(&mut default_path)?;

    let msvc = install_path.join(MSVC_PATH).join(default_path.trim());

    let enclave_lib_path = msvc.join(ENCLAVE_LIB_PATH);

    println!(
        "cargo::rustc-link-arg={}",
        Path::new(sdk_path)
            .join(UCRT_LIB_PATH)
            .to_str()
            .expect("Couldn't make string from ucrt.lib path")
    );

    // libvcruntime must come before vertdll or there will be duplicate external errors
    println!(
        "cargo::rustc-link-arg={}",
        enclave_lib_path
            .join("libvcruntime.lib")
            .to_str()
            .expect("Couldn't make string from libvcruntime.lib path")
    );
    println!(
        "cargo::rustc-link-arg={}",
        enclave_lib_path
            .join("libcmt.lib")
            .to_str()
            .expect("Couldn't make string from libcmt.lib path")
    );
    println!("cargo::rustc-link-arg=vertdll.lib");
    println!("cargo::rustc-link-arg=bcrypt.lib");

    Ok(())
}
