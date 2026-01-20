// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! User-Bound Key Sample Host Application
//!
//! Demonstrates loading a VBS enclave and using user-bound keys with Windows Hello.

#![allow(dead_code)]

mod edl_impls;

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

// VBS Enclave SDK for loading enclaves
use vbsenclave_sdk_host::KeyCredentialManager;
use vbsenclave_sdk_host::enclave::{EnclaveHandle, megabytes};
// SDK's userboundkey module for VTL0 callbacks
use vbsenclave_sdk_host::userboundkey::{UntrustedImpl as SdkUntrustedImpl, UserBoundKeyVtl0Host};

// Windows APIs for buffer conversion
use windows::Security::Cryptography::CryptographicBuffer;
use windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow;

// Generated host stubs for enclave calls
use userboundkey_sample_host_gen::implementation::types::edl::WString;
use userboundkey_sample_host_gen::stubs::trusted::userboundkey_sampleWrapper;

const KEY_NAME: &str = "MyEncryptionKey-001";
const PIN_MESSAGE: &str = "User-Bound Key Sample";

fn get_key_file_path() -> PathBuf {
    std::env::current_dir().unwrap().join(KEY_NAME)
}

fn get_encrypted_file_path() -> PathBuf {
    std::env::current_dir().unwrap().join("encrypted_userbound")
}

fn save_binary_data(path: &PathBuf, data: &[u8]) -> io::Result<()> {
    fs::write(path, data)
}

fn load_binary_data(path: &PathBuf) -> io::Result<Vec<u8>> {
    fs::read(path)
}

fn print_menu(is_key_loaded: bool) {
    println!("\n*** User-Bound Key Management and Encryption Menu ***");
    println!("1. Create UB Key");
    println!("2. Load UB Key");
    println!("3. Delete UB Key");
    println!("4. Encrypt Data");
    println!("5. Decrypt Data");
    println!("6. Exit");
    println!(
        "Key Status: {}",
        if is_key_loaded {
            "Loaded"
        } else {
            "Not Loaded"
        }
    );
    print!("Enter your choice: ");
    io::stdout().flush().unwrap();
}

/// Create a WString from a Rust string
fn to_wstring(s: &str) -> WString {
    let wchars: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
    WString { wchars }
}

/// Get secure ID from Windows Hello.
///
/// Returns the secure ID buffer that identifies this Windows Hello user.
fn get_secure_id_from_windows_hello() -> Result<Vec<u8>, String> {
    // Get the secure ID buffer from KeyCredentialManager
    let secure_id_buffer = KeyCredentialManager::GetSecureId()
        .map_err(|e| format!("Failed to get secure ID: {:?}", e))?;

    // Cast from userboundkey_kcm::IBuffer to windows::Storage::Streams::IBuffer
    let windows_buffer: windows::Storage::Streams::IBuffer =
        unsafe { std::mem::transmute(secure_id_buffer) };

    // Convert IBuffer to Vec<u8> using CryptographicBuffer
    let mut byte_array = windows::core::Array::<u8>::new();
    CryptographicBuffer::CopyToByteArray(&windows_buffer, &mut byte_array)
        .map_err(|e| format!("Failed to copy buffer: {:?}", e))?;

    Ok(byte_array.to_vec())
}

/// Load the enclave DLL and return the wrapper interface
fn load_enclave(
    enclave_path: &Path,
) -> Result<(EnclaveHandle, userboundkey_sampleWrapper), String> {
    println!("Loading enclave from: {}", enclave_path.display());

    // Try to get the secure ID from Windows Hello.
    // If Windows Hello isn't available, we continue without owner ID but key creation will fail.
    let owner_id = match get_secure_id_from_windows_hello() {
        Ok(id) => {
            println!("Got secure ID from Windows Hello ({} bytes)", id.len());
            Some(id)
        }
        Err(e) => {
            println!("Warning: Could not get secure ID from Windows Hello: {}", e);
            println!("Enclave will load but user-bound key operations may fail.");
            None
        }
    };

    // Create, load, and initialize the enclave (512MB)
    let enclave = EnclaveHandle::create_and_initialize(
        enclave_path,
        megabytes(512),
        owner_id.as_deref(), // Pass the secure ID as owner ID if available
    )
    .map_err(|e| format!("Failed to create/initialize enclave: {:?}", e))?;

    // Create the wrapper interface for enclave calls
    let wrapper = userboundkey_sampleWrapper::new(enclave.as_ptr());

    // Register the sample's VTL0 callbacks (for debug_print, etc.)
    wrapper
        .register_vtl0_callbacks::<edl_impls::UntrustedImpl>()
        .map_err(|e| format!("Failed to register sample callbacks: {:?}", e))?;

    // Register the SDK's VTL0 callbacks so enclave can call back to host
    // The SDK enclave functions (create_user_bound_key, etc.) use these callbacks
    let sdk_wrapper = UserBoundKeyVtl0Host::new(enclave.as_ptr());
    sdk_wrapper
        .register_vtl0_callbacks::<SdkUntrustedImpl>()
        .map_err(|e| format!("Failed to register SDK callbacks: {:?}", e))?;

    println!("Enclave loaded and callbacks registered successfully.");
    Ok((enclave, wrapper))
}

fn main() {
    println!("=== User-Bound Key Sample (Rust) ===");
    println!();

    // Get enclave DLL path (should be in same directory as host executable)
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| std::env::current_dir().unwrap());
    let enclave_path = exe_dir.join("userboundkey_sample_enclave.dll");

    // Load the enclave
    let (_enclave_handle, enclave) = match load_enclave(&enclave_path) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("Failed to load enclave: {}", e);
            eprintln!("Make sure {} exists.", enclave_path.display());
            return;
        }
    };

    let key_file_path = get_key_file_path();
    let encrypted_file_path = get_encrypted_file_path();
    let mut secured_key_bytes: Vec<u8> = Vec::new();
    let mut is_key_loaded = false;

    // Try to load existing key from file
    if key_file_path.exists() {
        if let Ok(data) = load_binary_data(&key_file_path) {
            secured_key_bytes = data;
            is_key_loaded = true;
            println!("Found existing key file: {}", key_file_path.display());
        }
    }

    // Window ID - use foreground window for Windows Hello prompts
    // GetForegroundWindow returns the handle of the window with which the user is currently working
    let window_id: u64 = unsafe { GetForegroundWindow().0 as u64 };

    loop {
        print_menu(is_key_loaded);

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            continue;
        }

        let choice: u32 = match input.trim().parse() {
            Ok(n) => n,
            Err(_) => {
                println!("Invalid input.");
                continue;
            }
        };

        match choice {
            1 => {
                // Create User-Bound Key
                println!("\n[Create User-Bound Key]");
                println!("Window ID: 0x{:X}", window_id);
                println!("Calling enclave... (Windows Hello prompt should appear)");

                let key_name = to_wstring(KEY_NAME);
                let pin_message = to_wstring(PIN_MESSAGE);

                // KeyCredentialCreationOption::ReplaceExisting = 1
                const REPLACE_EXISTING: u32 = 1;

                match enclave.CreateUserBoundKey(
                    &key_name,
                    &pin_message,
                    window_id,
                    REPLACE_EXISTING,
                ) {
                    Ok(key_bytes) => {
                        if save_binary_data(&key_file_path, &key_bytes).is_ok() {
                            println!("Key created and saved to: {}", key_file_path.display());
                            secured_key_bytes = key_bytes;
                            is_key_loaded = true;
                        } else {
                            eprintln!("Failed to save key to file.");
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to create key: {:?}", e);
                    }
                }
            }
            2 => {
                // Load User-Bound Key
                println!("\n[Load User-Bound Key]");
                if key_file_path.exists() {
                    match load_binary_data(&key_file_path) {
                        Ok(data) => {
                            secured_key_bytes = data;
                            is_key_loaded = true;
                            println!("Key loaded from: {}", key_file_path.display());
                        }
                        Err(e) => {
                            eprintln!("Failed to load key: {}", e);
                        }
                    }
                } else {
                    println!("No key file found. Create one first.");
                }
            }
            3 => {
                // Delete User-Bound Key
                println!("\n[Delete User-Bound Key]");
                if fs::remove_file(&key_file_path).is_ok() {
                    println!("Key file deleted.");
                    secured_key_bytes.clear();
                    is_key_loaded = false;
                } else {
                    println!("No key file to delete.");
                }
            }
            4 => {
                // Encrypt Data
                println!("\n[Encrypt Data]");
                if !is_key_loaded {
                    println!("Load or create a key first.");
                    continue;
                }

                print!("Enter text to encrypt: ");
                io::stdout().flush().unwrap();
                let mut text = String::new();
                if io::stdin().read_line(&mut text).is_err() {
                    continue;
                }

                let key_name = to_wstring(KEY_NAME);
                let pin_message = to_wstring(PIN_MESSAGE);
                let input_data = to_wstring(text.trim());

                match enclave.LoadUserBoundKeyAndEncryptData(
                    &key_name,
                    &pin_message,
                    window_id,
                    &secured_key_bytes,
                    &input_data,
                ) {
                    Ok(result) => {
                        // Check if key needs resealing
                        if result.needsReseal && !result.resealedEncryptionKeyBytes.is_empty() {
                            println!("Key was resealed, updating stored key...");
                            secured_key_bytes = result.resealedEncryptionKeyBytes;
                            if let Err(e) = save_binary_data(&key_file_path, &secured_key_bytes) {
                                eprintln!("Warning: Failed to save resealed key: {}", e);
                            }
                        }

                        // Save encrypted data
                        if save_binary_data(&encrypted_file_path, &result.combinedOutputData)
                            .is_ok()
                        {
                            println!("Encrypted data saved to: {}", encrypted_file_path.display());
                            println!("Encrypted {} bytes.", result.combinedOutputData.len());
                        } else {
                            eprintln!("Failed to save encrypted data.");
                        }
                    }
                    Err(e) => {
                        eprintln!("Encryption failed: {:?}", e);
                    }
                }
            }
            5 => {
                // Decrypt Data
                println!("\n[Decrypt Data]");
                if !encrypted_file_path.exists() {
                    println!("No encrypted data file found.");
                    continue;
                }
                if !is_key_loaded {
                    println!("Load or create a key first.");
                    continue;
                }

                let combined_data = match load_binary_data(&encrypted_file_path) {
                    Ok(data) => data,
                    Err(e) => {
                        eprintln!("Failed to load encrypted data: {}", e);
                        continue;
                    }
                };

                let key_name = to_wstring(KEY_NAME);
                let pin_message = to_wstring(PIN_MESSAGE);

                match enclave.LoadUserBoundKeyAndDecryptData(
                    &key_name,
                    &pin_message,
                    window_id,
                    &secured_key_bytes,
                    &combined_data,
                ) {
                    Ok(result) => {
                        // Check if key needs resealing
                        if result.needsReseal && !result.resealedEncryptionKeyBytes.is_empty() {
                            println!("Key was resealed, updating stored key...");
                            secured_key_bytes = result.resealedEncryptionKeyBytes;
                            if let Err(e) = save_binary_data(&key_file_path, &secured_key_bytes) {
                                eprintln!("Warning: Failed to save resealed key: {}", e);
                            }
                        }

                        // Convert WString to Rust String
                        let decrypted_text: String = result
                            .decryptedData
                            .wchars
                            .iter()
                            .take_while(|&&c| c != 0)
                            .map(|&c| char::from_u32(c as u32).unwrap_or('?'))
                            .collect();

                        println!("Decrypted data: {}", decrypted_text);
                    }
                    Err(e) => {
                        eprintln!("Decryption failed: {:?}", e);
                    }
                }
            }
            6 => {
                println!("Exiting.");
                break;
            }
            _ => println!("Invalid choice."),
        }
    }

    // EnclaveHandle will automatically terminate and delete the enclave on drop
    println!("Enclave cleanup complete.");
}
