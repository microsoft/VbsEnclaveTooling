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

### Prerequisites
1. Windows 10/11 with VBS support enabled
2. Visual Studio 2022 with C++ development tools
3. Windows SDK version 10.0.26100.2454 (minimum)
4. For HostAppUserBound: Windows SDK version 10.0.26100.7175 or later

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

## Common Features Across All Samples

- **Enclave Creation**: All samples create VBS enclaves with debug flags enabled
- **Error Handling**: Comprehensive error reporting using WIL (Windows Implementation Libraries)
- **Logging**: Integrated telemetry and logging support with configurable log levels
- **Interactive Menus**: User-friendly console interfaces for testing different scenarios
- **File I/O**: Secure storage and retrieval of encrypted data and keys
- **Debug Support**: Compatible with Visual Studio debugger and WinDbg for enclave debugging

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
- Ensure Windows Hello is set up with PIN or biometric authentication
- Verify TPM 2.0 is available and enabled
- Check that the required Windows SDK version (10.0.26100.7175) is installed
- Confirm hardware supports Windows Hello features

## Additional Resources

- [VBS Enclave Development Guide](https://learn.microsoft.com/windows/win32/trusted-execution/vbs-enclaves-dev-guide)
- [Visual Studio Remote Debugging](https://learn.microsoft.com/visualstudio/debugger/remote-debugging?view=vs-2022)
- [Windows Hello for Business](https://docs.microsoft.com/windows/security/identity-protection/hello-for-business/)
