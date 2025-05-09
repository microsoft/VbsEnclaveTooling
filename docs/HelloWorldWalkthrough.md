# Hello World VBS Enclave SDK Walkthrough

## Prerequisites:
 
* Windows SDK 10.0.26100.3916 or higher is installed. Latest SDK update is published to:
  * [https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/) 
 
* Follow instructions to build the repo to generate the 2 nuget packages:
  * https://github.com/microsoft/VbsEnclaveTooling?tab=readme-ov-file#build-instructions
 
### Prepare your dev environment
Full instructions can be found at [VBS Enclaves dev guide](https://learn.microsoft.com/en-us/windows/win32/trusted-execution/vbs-enclaves-dev-guide)

!IMPORTANT! The following steps turn off security features in Windows and allows unsigned drivers to load. Consider only doing so when needed for testing, or setup a test vm. 
* The device must have a TPM that is enabled in the BIOS.
* Ensure you are running on a device with Windows 11, version 10.0.26100.3916 or higher
* Turn off [Secure Boot](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/disabling-secure-boot?view=windows-11)
  * If Bitlocker is enabled, you will need access to your recovery keys
* Enable [Test Signing](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option). From an elevated command prompt, run the following and reboot: 
  * ```BCDEdit /set TESTSIGNING ON```
* Enable [Memory Integrity](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity?tabs=security). In the Windows Security app, go to Device Security -&gt; Core Integrity -&gt; and toggle Memory Integrity ON, then Reboot.

 
* Create a test certificate to use for signing the VBS Enclave. Replace "TheDefaultTestEnclaveCert" with the name you wish to create. eg:
    ``` 
    New-SelfSignedCertificate -CertStoreLocation Cert:\\CurrentUser\\My -DnsName "TheDefaultTestEnclaveCert" -KeyUsage DigitalSignature -KeySpec Signature -KeyLength 2048 -KeyAlgorithm RSA -HashAlgorithm SHA256 -TextExtension "2.5.29.37={text}1.3.6.1.5.5.7.3.3,1.3.6.1.4.1.311.76.57.1.15,1.3.6.1.4.1.311.97.814040577.346743379.4783502.105532346
    ```

## Solution structure
This sample will create a Host app, a DLL project and include a solution level file as follows:
- MyHostApp.sln
  - MySecretEnclave.edl
  - MyHostApp.vcxproj
    - main.cpp
  - MySecretEnclave.vcxproj
    - MySecretEnclaveExports.cpp

## Build the sample
### Create the initial host app project and solution
  1. Start VS, create new C++ Console App named **MyHostApp.vcxproj**
### Add the Enclave Definition Language file to the solution
  2. Add the Enclave Definition Language (EDL) file to the solution where you define your interface.
     * Right click on solution, add new item, text file, named **MySecretEnclave.edl**
     * Define a simple method for the enclave:
        ```c
        enclave
        {
            trusted
            {
                uint32_t DoSecretMath(
                    uint32_t val1,
                    uint32_t val2
                );
            };
        };
        ```
### Add the Enclave DLL project to the solution
Add a new DLL project and to the solution and configure it. This is the enclave dll.
1. Right click add project, DLL Project, name it **MySecretVBSEnclave.vcxproj**
1. Add references to the two nuget packages you created when you built the repro, located under \<repo root\>\\_build folder. Right-Click on the project, choose Manage NuGet packages – add a new package source for the _build folder where these were placed, and install the packages:
    * Microsoft.Windows.VbsEnclave.SDK.0.0.0.nupkg
    * Microsoft.Windows.VbsEnclave.CodeGenerator.0.0.0.nupkg
1. Update DLLMain.cpp with the enclave configuration information as follows. For more information on these values and how they impact enclave sealing policy, please refer to https://learn.microsoft.com/en-us/windows/win32/api/ntenclv/ne-ntenclv-enclave_sealing_identity_policy
    ```c
    #include "pch.h"
    #include <array>

    // Family ID will be assigned via Azure Trusted Signing
    // For private testing you can use any 16 byte value except 1 or 0
    #define SAMPLE_ENCLAVE_FAMILY_ID \
        { \
            0xED, 0X1D, 0xD0, 0x21, 0xC1, 0xB3, 0x42, 0x4C, \
            0x96, 0x49, 0xF6, 0xE9, 0x18, 0x18, 0x70, 0x36, \
        }
    
    #define SAMPLE_ENCLAVE_IMAGE_ID \
        { \
            0x9B, 0x9B, 0x50, 0xDD, 0x83, 0x2F, 0x44, 0xFD, \
            0xB3, 0x8D, 0xAD, 0x87, 0x92, 0xD6, 0x9F, 0x42, \
        }
    
    // Example version - 10.0.26100.0 -> A.0.65F4.00
    #define SAMPLE_ENCLAVE_IMAGE_VERSION 0xA065F400 

    // Security version number
    #define SAMPLE_ENCLAVE_SVN 1000
    
    #define ENCLAVE_ADDRESS_SPACE_SIZE \
        0x20000000          // The expected virtual size of the private address range 
                            // for the enclave, in bytes, in 2MB increments. (512MB)
                            // The host call to ::create(,,,<size>) must be the same value
    
    // Enclave image creation policies
    #ifndef ENCLAVE_MAX_THREADS
    #define ENCLAVE_MAX_THREADS 16
    #endif
    
    // Ensure we only enable debugging in DEBUG builds
    constexpr int EnclavePolicy_EnableDebuggingForDebugBuildsOnly
    {
    #ifdef _DEBUG
        IMAGE_ENCLAVE_POLICY_DEBUGGABLE
    #endif
    };
    
    // VBS enclave configuration - included statically
    extern "C" const IMAGE_ENCLAVE_CONFIG __enclave_config = {
        sizeof(IMAGE_ENCLAVE_CONFIG),
        IMAGE_ENCLAVE_MINIMUM_CONFIG_SIZE,
        IMAGE_ENCLAVE_POLICY_DEBUGGABLE,
        0,
        0,
        0,
        SAMPLE_ENCLAVE_FAMILY_ID,
        SAMPLE_ENCLAVE_IMAGE_ID,
        SAMPLE_ENCLAVE_IMAGE_VERSION,
        SAMPLE_ENCLAVE_SVN,
        ENCLAVE_ADDRESS_SPACE_SIZE,
        ENCLAVE_MAX_THREADS,
        IMAGE_ENCLAVE_FLAG_PRIMARY_IMAGE};
    
    BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID)
    {
        switch (reason)
        {
            case DLL_PROCESS_ATTACH:
                break;
            case DLL_PROCESS_DETACH:
                break;
            case DLL_THREAD_ATTACH:
                break;
            default:
                break;
        }
        return TRUE;
    }
    ```
1.	Unload the project file and edit it. Add new properties for the libraries and EDL code generator, typically placed after the default "User Macros" properties. 
    * Note the $(VBS_Enclave_Dependencies) path should be updated depending if you installed the Windows SDK 10.0.26100.3916+, or installed Microsoft.Windows.SDK.CPP & Microsoft.Windows.SDK.CPP.X64 & ARM64 nuget packages.
    * Update the name of the test certificate created earlier
    ```html
    <!-- ********* -->
    <!-- Paths to enclave libraries -->
    <!-- ********* -->
    <PropertyGroup Label="EnclaveLibs">
      <VC_LibraryPath_Enclave>$(VC_LibraryPath_VC_x64_Desktop)\enclave</VC_LibraryPath_Enclave>
      <WindowsSDK_LibraryPath_Enclave>
        $(WindowsSDK_LibraryPath)\..\ucrt_enclave\$(Platform)
      </WindowsSDK_LibraryPath_Enclave>
      <VBS_Enclave_Dependencies>
        vertdll.lib;
        bcrypt.lib;
        $(VC_LibraryPath_Enclave)\libcmt.lib;
        $(VC_LibraryPath_Enclave)\libvcruntime.lib;
        $(WindowsSDK_LibraryPath_Enclave)\ucrt.lib;
      </VBS_Enclave_Dependencies>
    </PropertyGroup>
    
    <!-- ********* -->
    <!-- EDL Code Generator properties -->
    <!-- ********* -->
    <PropertyGroup Label="EDL Codegen props">
      <VbsEnclaveEdlPath>$(ProjectDir)..\MySecretEnclave.edl</VbsEnclaveEdlPath>
      <VbsEnclaveNamespace>VbsEnclave</VbsEnclaveNamespace>
      <VbsEnclaveVirtualTrustLayer>Enclave</VbsEnclaveVirtualTrustLayer>
      <VbsEnclaveSkipCodegen>false</VbsEnclaveSkipCodegen>
    </PropertyGroup>
        
    <!-- ********* -->
    <!-- Property Group for Cert to sign with -->
    <!-- ********* -->
    <PropertyGroup Label="Test Signing certificate">
        <EnclaveCertName>TheDefaultTestEnclaveCertName</EnclaveCertName>
    </PropertyGroup>
    
    <!-- ********* -->
    <!-- Properties for Post-Build Commands -->
    <!-- ********* -->
    <PropertyGroup Label="Post-Build command props">
        <VEIID_Command>"$(WindowsSDKVersionedBinRoot)\$(PlatformTarget)\veiid.exe" "$(OutDir)$(TargetName)$(TargetExt)"</VEIID_Command> 
        <SIGNTOOL_Command>signtool sign /ph /fd SHA256 /n "$(EnclaveCertName)" "$(OutDir)$(TargetName)$(TargetExt)"</SIGNTOOL_Command>
    </PropertyGroup>

1. Add a Post-Build step to the build configurations
    <!-- ********* -->
    <!-- Post-Build steps - Apply VEIID protection and sign the enclave dll -->
    <!-- ********* -->
    <PostBuildEvent>
        <Command>$(VEIID_Command)</Command>
        <Message>Apply VEIID Protection</Message>
    </PostBuildEvent>
    <PostBuildEvent>
        <Command>$(SIGNTOOL_Command)</Command>
        <Message>Sign the enclave</Message>
    </PostBuildEvent>
    ```

1. Save and Reload the project. 
1. Via Project Properties, set C/C++ compilation settings:
   * Precompiled headers -> Not using 
   * Basic runtime checks –> Default
   * C++ Language Standard -> /std:c++ 20 (due to usage of span)
   * Conformance mode -> Yes (permissive-)
   * Library – MultiThreaded Debug /MTd, and /MT for Release builds

1.	Via Project Properties, Set Linker settings:
    * Enable Incremental Linking -> No (/INCREMENTAL:NO)
    * Ignore All Default Libraries -> Yes (/NODEFAULTLIB)
    * Add Additional Dependencies -> $(VBS_Enclave_Dependencies) 
    * For command line, add “additional options” -> /ENCLAVE /INTEGRITYCHECK /GUARD:MIXED
1.	Go to solution explorer and open PCH.H and update it:
      * Remove #include “framework.h”
      * Add the enclave header, winenclave.h, eg:
        ```cpp
        #ifndef PCH_H
        #define PCH_H
        
        // add headers that you want to pre-compile here
        // #include "framework.h"
        
        // DEMO - Step 1: Include the enclave header
        #include <winenclave.h>
        
        #endif //PCH_H
        ```
1.	Right click the dll project and choose “Build”. This will generate the projection layer for the enclave dll. You should have a couple initial error messages after code generation due to lack of implementation. We will fix this in the next step.
      * For reference on what the code generation built, choose 'Show All Files' in solution explorer and navigate to “Generated Files\VbsEnclave\Enclave\Exports\\". View **Implementations.h** which is of most interest. This file shows the marshalling of parameters and memory safety checks for the enclave.

1.	Add a cpp file to the dll project and name it “MySecretEnclaveExports.cpp”. This is where to put the code for the enclave logic. You need to reference the Implementations.h, and then implement the interface defined in the EDL file:
    ```cpp
    #include <VbsEnclave\Enclave\Implementations.h>
    
    uint32_t VbsEnclave::VTL1_Declarations::DoSecretMath(_In_  std::uint32_t val1, _In_  std::uint32_t val2)
    {
    	return val1*val2;
    }
    ```
1.	Choose Build again. There should be no errors, indicating the VBS Enclave is ready to be used.

### Build the host app
1. In MyHostApp.vcxproj, add reference to the nuget packages, via Right-Click, Manage NuGet packages and refer to the local nuget feed created earlier:
   * Microsoft.Windows.VBSEnclave.SDK 
   * Microsoft.Windows.VBSEnclave.CodeGenerator 
1. In project properties, set compiler and linker flags as follows:
   * Compiler -> C/C++ Language Standard, choose **ISO C++20 Standard (/std:c++20)**
   * Linker –> Input ->Additional Dependencies, edit the list to add "**onecore.lib**"
1. Add the projection layer properties to the project file
   * Unload the project file and edit it, adding the following properties. The trust layer is optional for the host – host is assumed if missing.
   * TIP - To keep these properties in sync between projects, consider moving the first 3 properties into a separate '.props' file and import that into both projects.
        ```html
          <!-- ************ -->
          <!-- VBS Enclave codegen properties for host -->
          <PropertyGroup>
            <VbsEnclaveEdlPath>$(ProjectDir)..\MySecretEnclave.edl</VbsEnclaveEdlPath>
            <VbsEnclaveVtl0ClassName>MySecretEnclave</VbsEnclaveVtl0ClassName>
            <VbsEnclaveNamespace>VbsEnclave</VbsEnclaveNamespace>
            <VbsEnclaveVirtualTrustLayer>HostApp</VbsEnclaveVirtualTrustLayer>
          </PropertyGroup>
          <!-- ************ -->
        ```
1.	Right-Click on the project and choose “Build”, it should succeed. 
1.	Choose “Show all files” in solution explorer and you should see the ‘Generated Files\VbsEnclave\HostApp” folder. To see the generated code, **Stubs.h** is of most interest to the host app.
1.	In your “main” method, initialize the enclave and call its methods
    * Add the host side include file from the SDK nuget package and the new Stubs.h code generated header.
        ```cpp
        #include <conio.h>
        #include <iostream>
        #include <veil\host\enclave_api.vtl0.h>
        #include <VbsEnclave\HostApp\Stubs.h>
        ```
    * Initialize the enclave and call its interface:
        ```cpp
        // Create app+user enclave identity
        auto ownerId = veil::vtl0::appmodel::owner_id();
    
        // Load enclave
        // We don't want DEBUG for a retail build!
        constexpr int EnclaveCreate_Flags {
        #ifdef _DEBUG
            ENCLAVE_VBS_FLAG_DEBUG
        #endif
        };
    
        #ifndef _DEBUG
            static_assert(flags & ENCLAVE_VBS_FLAG_DEBUG == 0, "Do not use DEBUG flag for retail builds");
        #endif
    
        auto flags = EnclaveCreate_Flags;

        // Memory allocation must match enclave configuration (512mb)
        auto enclave = veil::vtl0::enclave::create(ENCLAVE_TYPE_VBS, ownerId, flags,
                                                 veil::vtl0::enclave::megabytes(512));
        veil::vtl0::enclave::load_image(enclave.get(), L"MySecretVBSEnclave.dll");
        veil::vtl0::enclave::initialize(enclave.get(), 1);
    
        // Register framework callbacks
        veil::vtl0::enclave_api::register_callbacks(enclave.get());
    
        // Initialize enclave interface
        auto enclaveInterface = VbsEnclave::VTL0_Stubs::MySecretEnclave(enclave.get());
        THROW_IF_FAILED(enclaveInterface.RegisterVtl0Callbacks());
    
        //Call into the enclave
        auto secretResults = enclaveInterface.DoSecretMath(10, 20);
        wprintf(L"Result = %d\n", secretResults);
        wprintf(L"Press any key to exit.");
        _getch();
        ```
    
1. Now right click and choose Build. It should report success.
1. Press F5, and now you should be able to debug the sample app and see the result!
![alt text](image.png)