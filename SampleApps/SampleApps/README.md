# VBS Enclave Sample Applications

This repository contains four sample host applications demonstrating different aspects of Virtualization-based Security (VBS) enclave development. Each application showcases specific capabilities and use cases for secure enclave programming.

## Sample Applications Overview

### 1. HostApp - Basic Encryption/Decryption
**Location**: `HostApp/main.cpp`

This is the fundamental sample application that demonstrates:
- Basic VBS enclave creation and initialization
- Simple encryption and decryption workflows
- Enclave sealing and unsealing operations
- File-based storage of encrypted keys and data
- Interactive menu system for encrypt/decrypt operations

**Key Features**:
- Creates encryption keys within the secure enclave
- Encrypts user-provided strings using enclave-protected keys
- Saves encrypted data and authentication tags to disk
- Decrypts previously encrypted data using the same enclave
- Demonstrates basic host-to-enclave communication patterns

### 2. HostAppExploreThreadpool - Thread Pool Demonstration
**Location**: `HostAppExploreThreadpool/main.cpp`

A simple application focused on demonstrating VBS enclave thread pool capabilities:
- Creates a VBS enclave with multiple threads (3 threads)
- Demonstrates taskpool functionality within the enclave environment
- Shows how to initialize enclaves with specific thread counts
- Minimal example for understanding enclave threading concepts

**Key Features**:
- Multi-threaded enclave initialization
- `RunTaskpoolExample` demonstration
- Basic enclave thread management patterns

### 3. HostAppEncryptDecryptThreadpool - Multi-threaded Operations
**Location**: `HostAppEncryptDecryptThreadpool/main.cpp`

Sample demonstrating concurrent encryption and decryption operations:
- Encrypts multiple strings simultaneously using enclave thread pools
- Demonstrates parallel processing within secure enclaves
- Shows how to coordinate multiple encryption operations
- Handles concurrent file operations for encrypted data storage

**Key Features**:
- Simultaneous encryption of two strings in parallel
- Thread-safe enclave operations
- Concurrent data processing with proper synchronization
- Multiple file handling (encrypted1, encrypted2, tag1, tag2)
- Interactive workflow for multi-threaded scenarios

### 4. HostAppUserBound - Windows Hello Integration
**Location**: `HostAppUserBound/main.cpp`

Sample demonstrating user-bound encryption using Windows Hello:
- Integrates with Windows Hello biometric authentication
- Creates encryption keys bound to the current user's identity
- Uses Windows Security Credential APIs for user authentication
- Demonstrates hardware-backed security features

**Key Features**:
- User identity-bound encryption keys
- Windows Hello PIN/biometric authentication integration
- Hardware TPM integration for secure key storage
- User-specific enclave owner ID generation using `GetSecureId`
- Automatic key re-sealing when needed
- Comprehensive error handling for authentication failures

**Requirements**:
- **Microsoft.Windows.SDK.CPP version 10.0.26100.7175** or later for the new user binding APIs
- Windows Hello setup on the target machine
- Compatible biometric hardware or PIN authentication
- TPM 2.0 support for hardware-backed security

**NuGet Package Links**:
- [Microsoft.Windows.SDK.CPP 10.0.26100.7175](https://nuget.info/packages/Microsoft.Windows.SDK.CPP/10.0.26100.7175)
- [Microsoft.Windows.SDK.CPP.x64 10.0.26100.7175](https://nuget.info/packages/Microsoft.Windows.SDK.CPP.x64/10.0.26100.7175)

## Getting Started

### Build Machine Prerequisites
1. Visual Studio 2022 with C++ development tools
2. Windows SDK version 10.0.26100.2454 (minimum)
3. For HostAppUserBound: Windows SDK version 10.0.26100.7175 or later

### Target Machine or VM Prerequisites
1. Windows 10/11 with VBS support enabled
2. The [x64 Microsoft Visual C++ Redistributable](https://learn.microsoft.com/cpp/windows/latest-supported-vc-redist),
   installed once on the target machine. Use a version at least as recent as the
   MSVC build tools used to compile the samples.
3. Trust the enclave signing certificate on the target machine.
4. For user-bound samples, configure Windows Hello for the account running them.

The Windows SDK and C++ build tools are build-machine dependencies; they are not
required on a VM used only to run the compiled samples. Deploy the sample
executables and their enclave/SDK DLLs. The deployment helper relies on the
installed Visual C++ Redistributable rather than copying MSVC runtime DLLs.

### Build Instructions
1. Build both the `Microsoft.Windows.VbsEnclave.CodeGenerator` and the `Microsoft.Windows.VbsEnclave.SDK` NuGet packages by running the build script [here](../../buildScripts/build.ps1).
2. Open the solution in Visual Studio
3. Build the desired sample application
4. Ensure `SampleEnclave.dll` is available in the output directory

### Running in a VM using Visual Studio
1. Create a VM and enable: **Windows Security → Device Security → Core Isolation → Memory integrity**. Restart the VM.
2. Please make sure you have Microsoft.Windows.SDK.cpp version 10.0.26100.2454 installed on your host machine where you would be building code. You may have to downgrade your SDK version if needed.
3. Install Visual Studio Remote Debugger in your VM: https://learn.microsoft.com/visualstudio/debugger/remote-debugging?view=vs-2022
4. Set up Visual Studio remote debugger for the Host app: https://learn.microsoft.com/visualstudio/debugger/remote-debugging?view=vs-2022
5. Make sure you have the enclave dll available in the working directory of the VM. You can specify the absolute dll path in Visual Studio → SampleHostApp → Properties → Debugging → Remote Windows Debugger → Additional files to let VS do place it on the VM.
6. F5 on Visual Studio will launch the app on your VM.
7. You should be able to set breakpoints in host and debug. You can use debug_print commands in the Enclave code to help debug.
8. You could also launch the host app and use Windbg → Attach to process to debug code inside the enclave.

## Scripted Encryption Sample Validation

`buildScripts\Invoke-SampleNonceValidation.ps1` exercises Basic, Threadpool,
C++ user-bound, and Rust user-bound encryption. It does not run
`HostAppExploreThreadpool` or test every sample feature.

### Prepare a VM bundle

On the build machine, run `buildScripts\Deploy-SampleNonceValidation.ps1` with
the target Hyper-V VM name, credentials, and C++ and Rust output directories:

```powershell
.\buildScripts\Deploy-SampleNonceValidation.ps1 `
    -VMName MyTestVM -Credential (Get-Credential) `
    -CppOutputDirectory C:\build\cpp `
    -RustOutputDirectory C:\build\rust
```

The helper creates a new VM directory containing the binaries, validation script,
this README, and a SHA-256 manifest. It prints the destination. It does not
install the Visual C++ Redistributable, configure VBS, install the enclave signing
certificate, or enroll Windows Hello; prepare those separately before testing.

### Run one sample and test group at a time

Open 64-bit PowerShell in the VM's basic console session and change to the
deployed bundle directory. Check file hashes and VBS readiness without creating
keys or launching samples:

```powershell
.\Invoke-SampleNonceValidation.ps1 -PreflightOnly
```

Preflight does not verify Visual C++ Redistributable installation or Windows
Hello readiness. Install the runtime first; user-bound tests also require Hello
configured for the account running the script.

| `-Sample` | Application | Windows Hello |
|---|---|---|
| `Basic` (default) | `HostApp.exe` | No |
| `Threadpool` | `HostAppEncryptDecryptThreadpool.exe` | No |
| `CppUserBound` | `HostAppUserBound.exe` | Yes |
| `RustUserBound` | `userboundkey-sample.exe` | Yes |
| `All` | All four applications above | Yes |

| `-TestGroup` | Checks |
|---|---|
| `Nonce` (default) | Valid round trips; parallel nonce uniqueness for Threadpool; restarted-key and live cached-key nonce uniqueness for user-bound samples, including decryption of both cached-key outputs |
| `Tampering` | A valid baseline round trip, followed by nonce, tag, ciphertext, and truncation rejection; Threadpool checks worker 1, worker 2, and both |
| `All` | Both groups |

For example, run each of these separately:

```powershell
.\Invoke-SampleNonceValidation.ps1 -Sample CppUserBound -TestGroup Nonce
.\Invoke-SampleNonceValidation.ps1 -Sample RustUserBound -TestGroup Nonce
.\Invoke-SampleNonceValidation.ps1 -Sample Threadpool -TestGroup Tampering
```

By default, each run uses one nonempty input. Add `-IncludeEmptyInput` to repeat
the selected checks with empty input; ciphertext corruption is skipped for empty
ciphertext. To request the full matrix explicitly:

```powershell
.\Invoke-SampleNonceValidation.ps1 -Sample All -TestGroup All -IncludeEmptyInput
```

### Windows Hello prompts and results

**Use a disposable test account.** User-bound tests replace the Windows Hello
sample credential `MyEncryptionKey-001`, which can invalidate existing sample
keys and data. Enter the exact confirmation `RUN TESTS` to proceed.

Each test step prints its sample, purpose, log path, and any expected Hello
approval before launching the sample. Most steps start a fresh enclave and need
to unlock the key again. A user-bound `Nonce` run starts four sample processes per
input; initial key creation can require an additional approval. The cached-key
step performs two encryptions and decrypts both outputs within one process.
Selecting both user-bound samples or adding empty input requires more approvals.

Tampering cases are labeled `EXPECTED FAILURE`: sample authentication or format
errors are intentional. The script must still verify the expected rejection.
A final exception or a `FAIL` result is not a successful run.

Each run creates a fresh `results\<timestamp>-<id>` directory containing
`results.csv`, sample logs, and test key/data files. Only manifest-listed
executables and DLLs are copied into test directories, not files from manual
sample runs. Preserve the logs when reporting a failure.

## Common Features Across All Samples

- **Enclave Creation**: All samples create VBS enclaves with debug flags enabled
- **Error Handling**: Comprehensive error reporting using WIL (Windows Implementation Libraries)
- **Logging**: Integrated telemetry and logging support with configurable log levels
- **Interactive Menus**: User-friendly console interfaces for testing different scenarios
- **File I/O**: Secure storage and retrieval of encrypted data and keys
- **Debug Support**: Compatible with Visual Studio debugger and WinDbg for enclave debugging

## Encrypted Data Formats

Each AES-GCM encryption uses a fresh, cryptographically random 12-byte nonce,
including each message encrypted by the threadpool.

The x64 C++ samples store binary files with an 8-byte little-endian payload length
before the payload. The layouts below describe the payload, excluding that prefix.

- `HostApp` and `HostAppEncryptDecryptThreadpool` store `[nonce (12 bytes)][ciphertext]`
  in the `encrypted` or `encrypted1`/`encrypted2` files. The corresponding `tag`
  or `tag1`/`tag2` file contains the 16-byte authentication tag.
- `HostAppUserBound` stores
  `[tag_size (4 bytes, little-endian)][tag (16 bytes)][nonce (12 bytes)][ciphertext]`
  in `encrypted_userbound`.

Ciphertext without a stored nonce is not supported. Recreate encrypted data in
this format, using new keys if the existing keys were used with fixed nonces.

## Developer Flow: Create a Host App, Encrypt and Decrypt Data in Enclave

### Steps
1. In your host app set up enclave as shown below:
```cpp
// Create app+user enclave identity
auto ownerId = veil::vtl0::appmodel::owner_id();

// Load enclave
auto flags = ENCLAVE_VBS_FLAG_DEBUG;

auto enclave = veil::vtl0::enclave::create(ENCLAVE_TYPE_VBS, ownerId, flags, veil::vtl0::enclave::megabytes(512));
veil::vtl0::enclave::load_image(enclave.get(), L"SampleEnclave.dll");
veil::vtl0::enclave::initialize(enclave.get(), 1);

// Register framework callbacks
veil::vtl0::enclave_api::register_callbacks(enclave.get());
```

2. Create enclave dll - SampleEnclave.dll

   Refer to VBS Enclave development guide: https://learn.microsoft.com/windows/win32/trusted-execution/vbs-enclaves-dev-guide. Make sure you have made the following [changes to the compiler and linker configurations of your Enclave dll](https://learn.microsoft.com/windows/win32/trusted-execution/vbs-enclaves-dev-guide#:~:text=Before%20we%20can%20build%20the%20test%20enclave%20DLL%2C%20some%20changes%20to%20the%20compiler%20and%20linker%20configurations%20are%20required%3A) (VS dll).

3. Telemetry support
   - We support telemetry strings from the Enclave that are 2048 chars or shorter. Refer to telemetry usage in the sample app.
   - Telemetry files are stored in user specified dir or the current working directory (by default).

## Debugging Tips

- Use `debug_print` statements in enclave code for debugging output
- Debug output appears in the debugger, not the console (use DebugView if needed)
- Set breakpoints in both host and enclave code during remote debugging
- Attach WinDbg to the process for advanced enclave debugging scenarios

## Known Issues and Troubleshooting

### Certificate Issues
If you encounter "No certificates were found that met all the given criteria":
- Make sure to go through Step 3 in https://learn.microsoft.com/windows/win32/trusted-execution/vbs-enclaves-dev-guide and run the following commands:
```powershell
PS C:\WINDOWS\system32> New-SelfSignedCertificate -CertStoreLocation Cert:\CurrentUser\My -DnsName "TheDefaultTestEnclaveCertName" -KeyUsage DigitalSignature -KeySpec Signature -KeyLength 2048 -KeyAlgorithm RSA -HashAlgorithm SHA256 -TextExtension "2.5.29.37={text}1.3.6.1.5.5.7.3.3,1.3.6.1.4.1.311.76.57.1.15,1.3.6.1.4.1.311.97.814040577.346743380.4783503.105532347"
```
- You would see the following:
```
PSParentPath: Microsoft.PowerShell.Security\Certificate::CurrentUser\My

Thumbprint                                Subject
----------                                -------
4BCEEFFE327F46DFB2401F3460123BB016B50C22  CN=TheDefaultTestEnclaveCertName
```

### Windows Hello Issues (HostAppUserBound)
- Set up Windows Hello PIN or biometric authentication for the account running
  the sample inside the VM, under **Settings > Accounts > Sign-in options**.
- Run from the VM's basic console session. An empty `GetSecureId` result prevents
  the user-bound sample from starting; a Windows Hello prompt is not shown at this stage.
- Basic and threadpool encryption do not use Windows Hello and do not show authentication prompts.
- Verify TPM 2.0 is available and enabled
- Check that the required Windows SDK version (10.0.26100.7175) is installed
- Confirm hardware supports Windows Hello features

## Additional Resources

- [VBS Enclave Development Guide](https://learn.microsoft.com/windows/win32/trusted-execution/vbs-enclaves-dev-guide)
- [Visual Studio Remote Debugging](https://learn.microsoft.com/visualstudio/debugger/remote-debugging?view=vs-2022)
- [Windows Hello for Business](https://docs.microsoft.com/windows/security/identity-protection/hello-for-business/)

## Debug Print Flags and Scenarios

Understanding debug output behavior is crucial for effective development and troubleshooting of VBS enclave applications. Different debug flags control output at various layers of the system.

### Debug Flags Summary

1. **`_DEBUG`**: Standard Visual Studio debug build configuration flag
2. **`is_enclave_full_debug_enabled()`**: Derived from the `ENCLAVE_VBS_FLAG_DEBUG` flag passed to `CreateEnclave`
3. **`_VEIL_INTERNAL_DEBUG`**: VEIL framework internal debug flag that can be overridden via command line or parent props files

### Enabling _VEIL_INTERNAL_DEBUG

To enable VEIL internal debug output, add the following to your command line arguments:
```
/D_VEIL_INTERNAL_DEBUG
```

Or add it to your project's preprocessor definitions.

### Debug Output Scenarios

| Scenario | VTL0 (Host) Debug Prints | VTL1 (Enclave) Debug Prints | Requirements |
|----------|-------------------------|------------------------------|-------------|
| **Sample VTL0** | ✅ Enabled | ❌ Disabled | `_DEBUG` enabled |
| **Sample VTL1** | ❌ Disabled | ✅ Enabled | `is_enclave_full_debug_enabled()` enabled |
| **VEIL VTL0** | ✅ Enabled | ❌ Disabled | `_VEIL_INTERNAL_DEBUG` enabled |
| **VEIL VTL1** | ❌ Disabled | ✅ Enabled | `_VEIL_INTERNAL_DEBUG` AND `is_enclave_full_debug_enabled()` enabled |

### Usage Guidelines

- **Sample Applications**: Use `is_enclave_full_debug_enabled()` for enclave debug output that respects the enclave debug policy
- **Host Applications**: Use `_DEBUG` flag for standard debug builds
- **VEIL Framework**: Use `_VEIL_INTERNAL_DEBUG` for framework-level debugging
- **Production**: Ensure all debug flags are disabled for production builds to maintain security
