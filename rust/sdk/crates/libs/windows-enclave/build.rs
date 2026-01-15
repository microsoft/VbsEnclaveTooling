// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::fs;
use windows_bindgen::bindgen;

const BCRYPT_FILE_NAME: &str = "bcrypt.txt";
const VERTDLL_FILE_NAME: &str = "vertdll.txt";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Only rerun if the windows bindgen txt files change
    let build_dir = std::env::var("CARGO_MANIFEST_DIR")?;
    let bcrypt_path = format!("{}/apis/{}", build_dir, BCRYPT_FILE_NAME);
    let vertdll_path = format!("{}/apis/{}", build_dir, VERTDLL_FILE_NAME);
    println!("cargo:rerun-if-changed={}", bcrypt_path);
    println!("cargo:rerun-if-changed={}", vertdll_path);

    let out_dir: String = std::env::var("OUT_DIR")?;

    // replace the {0} placeholder in the binding txt files with the actual output path
    let bcrypt_contents = replace_placeholder("{0}", &bcrypt_path, &out_dir)?;
    let vertdll_contents = replace_placeholder("{0}", &vertdll_path, &out_dir)?;

    let content_slice = &[
        (BCRYPT_FILE_NAME, &bcrypt_contents),
        (VERTDLL_FILE_NAME, &vertdll_contents),
    ];

    // write the updated contents to temporary files for bindgen to consume
    for (file_name, contents) in content_slice {
        let temp_file_path = format!("{}/{}", out_dir, file_name);
        fs::write(&temp_file_path, contents)?;
        bindgen(["--etc", &temp_file_path]).unwrap();
    }

    update_vertdll_bindings(&out_dir)?;
    Ok(())
}

fn replace_placeholder(pattern: &str, path: &str, replacement: &str) -> std::io::Result<String> {
    let contents = fs::read_to_string(path)?;
    let updated_str = contents.replace(pattern, replacement);
    Ok(updated_str)
}

// The metadata doesn't currently support these functions so here we manually patch the link macro
// to import them from vertdll.dll unilaterally.
fn update_vertdll_bindings(output_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let vertdll_output_path = format!("{}/vertdll.rs", output_path);
    let bindings = std::fs::read_to_string(&vertdll_output_path)?;

    // Replace all occurrences of link!("<any dll>" ... with link!("vertdll.dll"
    let regex = regex::Regex::new(r#"link!\(".*?""#)?;
    let bindings = regex.replace_all(&bindings, r#"link!("vertdll.dll""#);

    std::fs::write(&vertdll_output_path, bindings.as_bytes())?;
    Ok(())
}
