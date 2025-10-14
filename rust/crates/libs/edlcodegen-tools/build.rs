use std::{env, fs, io::Cursor, io::Read, path::Path};
use zip::ZipArchive;

fn main() {
    let out_dir = env::var("OUT_DIR").expect("missing OUT_DIR");
    let tool_dir = Path::new(&out_dir).join("tools");
    fs::create_dir_all(&tool_dir).expect("failed to create tools dir");

    // Note: we use the azure feed to retrieve the nuget package since nuget.org is blocked in OneBranch pipelines.
    let version = "0.1.2-prerelease.250820.1";
    let url = format!(
        "https://pkgs.dev.azure.com/shine-oss/VbsEnclaveTooling/_apis/packaging/feeds/VbsEnclaveToolingDependencies/nuget/packages/Microsoft.Windows.VbsEnclave.CodeGenerator/versions/{version}/content?api-version=7.1-preview.1"
    );

    println!("Downloading Microsoft.Windows.VbsEnclave.CodeGenerator package from Azure feed...");

    // Download the .nupkg file
    let response = ureq::get(&url)
        .call()
        .expect("failed to download NuGet package");

    let mut reader = response.into_body().into_reader();
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .expect("failed to read response bytes");

    // Extract the NuGet package (ZIP format)
    let cursor = Cursor::new(bytes);
    let mut archive = ZipArchive::new(cursor).expect("invalid zip file");
    archive
        .extract(&tool_dir)
        .expect("failed to extract NuGet package");

    // Verify expected binaries exist
    let edl_path = tool_dir.join("bin\\edlcodegen.exe");
    let flatc_path = tool_dir.join("vcpkg\\tools\\flatbuffers\\flatc.exe");
    assert!(
        edl_path.exists(),
        "Missing bin\\edlcodegen.exe in NuGet package"
    );
    assert!(
        flatc_path.exists(),
        "Missing tools\\flatbuffers\\flatc.exe in NuGet package"
    );

    // Export environment variables for dependents
    println!(
        "cargo:rustc-env=EDLCODEGEN_TOOL_PATH={}",
        tool_dir.display()
    );
}
