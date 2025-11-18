# FuzzTests.exe - VBS Enclave Fuzzing Guide

This guide explains how to build and run the FuzzTests.exe application for fuzzing VBS Enclave functionality in VTL0 locally using LibFuzzer.

## Overview

FuzzTests.exe is a LibFuzzer-enabled application that targets the `RunEncryptionKeyExample_CreateEncryptionKey` function in the 
VBS Enclave SDK. It uses coverage-guided fuzzing to test encryption key generation and sealing operations within a secure enclave 
environment.

## Prerequisites

- Visual Studio 2022 (v17.14 or later)
- Windows SDK 10.0.26100.3916 or higher
- Access to OS.2020 repository for VertEmu and ASAN runtime components

## Setup Instructions

**Note**: Steps 1-8 below are for documentation purposes and have already been implemented in this sample codebase.

### 1. Built and Configured VertEmu

The VertEmu component has been built from the OS repository:

```
# Clone and build vertemu from:
# https://microsoft.visualstudio.com/OS/_git/os.2020?path=%2Fonecoreuap%2Fsdktools%2Fvertemu
```

**Important Hotfix Applied:**
The following fix was applied in `dllmain.c` (around lines 234-236):
```c
// Changed the return value to TRUE instead of the original return value
return TRUE;
```

The built `vertdll.dll` has been placed in the project's debug build output directory:
```
<ProjectRoot>\SampleApps\SampleApps\_build\x64\Debug\vertdll.dll
```

### 2. Copied ASAN Runtime

The AddressSanitizer runtime DLL has been copied from the OS.2020 repository:
```
Source: <OS.2020>\tools\vc\ASANSdk\bin\amd64\clang_rt.asan_dynamic-x86_64.dll
Destination: <ProjectRoot>\SampleApps\SampleApps\_build\x64\Debug
```

### 3. Modified Sample Enclave Linker Settings

For the SampleEnclave project, the linker configuration has been updated:

**Removed these linker options:**
- `/INTEGRITYCHECK`
- `/GUARD:MIXED`

**Updated these properties:**
- Set `IgnoreAllDefaultLibraries` to `false` (for both SampleEnclave and veil enclave lib)
- Removed `$(VBS_Enclave_Dependencies)` from Additional Dependencies

### 4. Updated SDK Configuration

Modified the `Microsoft.Windows.VbsEnclave.shared.targets` file:
- Commented out the section that adds `$(VBS_Enclave_Dependencies)` to projects consuming the codegen's additional options

### 5. Enabled Fuzzer Support for FuzzTests Project

The FuzzTests project has been configured to enable fuzzer support:

1. **FuzzTests project Properties** have been updated
2. **C/C++** ? **All Options** ? **Enable Fuzzer Support** set to **Yes (/fsanitize=fuzzer)**
3. The following has been added to the FuzzTests `.vcxproj` file:
```xml
<ItemDefinitionGroup>
  <ClCompile>
  <EnableFuzzer>true</EnableFuzzer>
  </ClCompile>
</ItemDefinitionGroup>
```

### 6. Rebuilt VBS Enclave Components

The build script has been executed to regenerate the CodeGenerator and SDK:
```powershell
.\buildScripts\build.ps1
```

### 7. Configured FuzzTests Project

In the FuzzTests project file (`.vcxproj`), the following has been added:
```xml
<PropertyGroup>
    <VbsEnclaveConsumeCppSupportLib>false</VbsEnclaveConsumeCppSupportLib>
</PropertyGroup>
```

### 8. Enabled LibFuzzer

The FuzzTests project has been configured for fuzzing with:
- LibFuzzer compilation flags added
- Required fuzzer entry points exported:
  - `LLVMFuzzerTestOneInput`

### 9. Build and Run

1. **Build the FuzzTests project:**
```bash
# Build in Visual Studio or use MSBuild
MSBuild FuzzTests.vcxproj /p:Configuration=Debug /p:Platform=x64
```

2. **Run locally for testing:**
```bash
# Basic execution test
FuzzTests.exe

# Run with LibFuzzer (example)
FuzzTests.exe -help
```

## Target Function

The fuzzer targets `RunEncryptionKeyExample_CreateEncryptionKey` which:
- Generates symmetric encryption keys within the secure enclave
- Tests key sealing operations using VBS enclave security features
- Validates logging functionality with various activity levels
- Exercises cryptographic operations in the trusted execution environment

## Input Structure

The fuzzer uses a structured input format:
```cpp
struct FuzzInput {
    uint32_t activity_level;        // Activity level for logging (1-5)
    uint32_t logFilePathLength;   // Length of log file path string in bytes
    // Variable length data follows: logFilePath (wide character string)
};
```

## Useful Links

- [LibFuzzer Documentation](https://llvm.org/docs/LibFuzzer.html)
- [VBS Enclave Fuzzing Guide](https://eng.ms/docs/cloud-ai-platform/azure-edge-platform-aep/aep-security/security-fundamentals/the-onefuzz-service/onefuzz/fuzzeronboarding/windowsdockedv2/vbsenclavefuzzing)
- [VertEmu Test References](https://microsoft.visualstudio.com/OS/_git/os.2020?path=%2Fminkernel%2Fium%2Ftests%2Fiumtests%2Fvertemutest)

