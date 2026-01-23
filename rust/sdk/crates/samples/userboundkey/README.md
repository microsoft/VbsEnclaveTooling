# User-Bound Key Sample

This sample demonstrates how to use the VBS Enclave SDK's user-bound key functionality
to create Windows Hello-protected encryption keys that are sealed to the enclave.

## Overview

The sample consists of:

- **`userboundkey_sample.edl`** - EDL interface defining the sample's trusted functions
- **`enclave/`** - Enclave DLL that implements the encryption/decryption logic
- **`host/`** - Host application with a menu-driven interface

## Features

1. **Create User-Bound Key** - Creates a new encryption key protected by Windows Hello
   and sealed to the enclave using VBS enclave sealing.

2. **Load User-Bound Key** - Loads an existing sealed key (triggers Windows Hello prompt).

3. **Delete User-Bound Key** - Removes the sealed key file.

4. **Encrypt Data** - Loads the key and encrypts user-provided text.

5. **Decrypt Data** - Loads the key and decrypts previously encrypted data.

## Security Model

- The encryption key is generated inside the VTL1 enclave
- The key is sealed using VBS enclave sealing (bound to enclave identity)
- Windows Hello biometric/PIN is required to access the key
- The cache configuration is set securely in VTL1 (VTL0 cannot influence it)
- Key material never leaves the enclave in plaintext

## Building

### Prerequisites

Building the enclave DLL requires:
- Windows SDK with VBS enclave libraries (`ucrt_enclave`)
- SDK versions 10.0.19041.0, 10.0.22621.0, or 10.0.26100.0 are known to work
- Visual Studio 2022 with MSVC enclave toolchain
- A code signing certificate for VBS enclaves (see below)

To verify your SDK has the required libraries:
```powershell
Test-Path "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\ucrt_enclave"
```

### Quick Build (Recommended)

Use the provided build script that generates EDL bindings, builds, and signs in one step:

```powershell
cd C:\VbsEnclaveTooling\rust\sdk

# Build with your signing certificate
.\generate_and_build_crates.ps1 -CertName "YourCertificateName"

# For release build
.\generate_and_build_crates.ps1 -Configuration release -CertName "YourCertificateName"
```

The script performs:
1. **Generate EDL bindings** - Creates Rust bindings from all EDL files (SDK + samples)
2. **Build** - Compiles entire SDK workspace including samples
3. **Sign** - Signs all enclave DLLs with veiid.exe and signtool

### EDL Generation Only

If you're working on EDL files and want fast intellisense updates without building:

```powershell
cd C:\VbsEnclaveTooling\rust\sdk

# Generate EDL bindings only (fast)
.\generate_codegen_for_workspace.ps1
```

### Manual Build Commands

If you prefer manual steps:

```powershell
# From the rust/sdk directory

# Build host application only (always works)
cargo build -p userboundkey-sample-host

# Build enclave (requires proper Windows SDK with ucrt_enclave)
cargo build -p userboundkey-sample-enclave

# Sign the enclave (required before running)
..\..\scripts\sign-enclave.ps1 -DllPath "target\debug\userboundkey_sample_enclave.dll" -CertName "YourCertificateName"

# Check compilation without linking (useful for CI)
cargo check --all-features
```

### Creating a Test Signing Certificate

To create a self-signed test certificate for development:

```powershell
# Create a self-signed certificate (run as Administrator)
$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=MyTestEnclaveCert" -CertStoreLocation Cert:\CurrentUser\My
```

## Running

### Prerequisites for Running

1. **Windows 11** with VBS (Virtualization Based Security) enabled
2. **Windows Hello** configured (PIN, fingerprint, or facial recognition)
3. **Developer Mode** enabled (optional, for debug enclaves)

To verify VBS is enabled:
```powershell
# Check VBS status
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Select-Object VirtualizationBasedSecurityStatus
# 2 = Running
```

### Steps to Run

1. **Build the sample using the build script:**
   ```powershell
   cd C:\VbsEnclaveTooling\rust\sdk
   .\generate_and_build_crates.ps1 -CertName "YourCertificateName"
   ```

2. **Run the sample:**
   ```powershell
   cd C:\VbsEnclaveTooling\rust\sdk\target\debug
   .\userboundkey-sample.exe
   ```

3. **Use the interactive menu:**
   ```
   === User-Bound Key Sample (Rust) ===
   
   *** User-Bound Key Management and Encryption Menu ***
   1. Create UB Key      <- First, create a new user-bound key
   2. Load UB Key        <- Load existing key from file
   3. Delete UB Key      <- Delete the key file
   4. Encrypt Data       <- Encrypt text (requires key)
   5. Decrypt Data       <- Decrypt data (requires key)
   6. Exit
   ```

### Typical Workflow

1. **Select option 1** to create a new user-bound key
   - Windows Hello prompt will appear (PIN/biometric)
   - Key is created and saved to `MyEncryptionKey-001`

2. **Select option 4** to encrypt data
   - Enter text when prompted
   - Windows Hello prompt may appear to unlock the key
   - Encrypted data saved to `encrypted_userbound`

3. **Select option 5** to decrypt data
   - Windows Hello prompt may appear
   - Decrypted text is displayed

### Troubleshooting

**"Failed to load enclave"**
- Ensure VBS is enabled in Windows settings
- Check that the enclave DLL exists next to the host executable
- Try running as Administrator

**"Windows Hello prompt does not appear"**
- Ensure Windows Hello is configured in Settings > Accounts > Sign-in options
- Try creating a new key (option 1)

**"Key needs resealing"**
- This is normal after enclave updates
- The sample automatically handles resealing

## Files Created

When running the sample, the following files are created in the current directory:

- `MyEncryptionKey-001` - The sealed encryption key
- `encrypted_userbound` - Encrypted data output

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Host Application (VTL0)                  │
│  - Menu interface                                           │
│  - File I/O for sealed keys and encrypted data              │
│  - Calls enclave via EDL interface                          │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ EDL Interface
                              │ (CreateUserBoundKey, LoadAndEncrypt, LoadAndDecrypt)
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                     Enclave DLL (VTL1)                       │
│  - Creates/loads user-bound keys via SDK                    │
│  - Performs encryption/decryption                           │
│  - Manages key caching                                      │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ SDK userboundkey module
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                 Windows Hello / KCM (VTL0)                   │
│  - Biometric/PIN authentication                             │
│  - Key Credential Manager                                   │
└─────────────────────────────────────────────────────────────┘
```

## Key Reseal

If the enclave's sealing key has changed (e.g., after an enclave update), the SDK
will automatically detect this and provide resealed key bytes. The sample handles
this by saving the resealed key back to disk.
