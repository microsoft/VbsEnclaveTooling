VBS enclave tooling
================

The VBS enclave tooling repository provides both a `CodeGenerator` and an `SDK` nuget package to make developing
features that interact with a VBS enclave easier. To learn more about VBS enclaves you can view the official documentation 
[here](https://learn.microsoft.com/windows/win32/trusted-execution/vbs-enclaves).

#### Language support for CodeGenerator and SDK
|             | HostApp | Enclave |
|-------------|---------|---------|
| C++ 20      | ✅      | ✅     |
| C++ 17      | ✅      | ❌     |
| Rust 1.88+  | ✅      | ✅     |

#### Operating System Support

| OS                  | Build                 |
|---------------------|-----------------------|
| Windows 11 24H2     | `26100.3916 or later` |

Developers will need to make sure they have `Windows SDK version 26100.7463` or later installed on their system or
integrated into their Visual Studio projects for user binding API support.

The Windows SDK can be installed in one of the following ways:
1. via installing the `Windows 11 SDK (10.0.26100.0)` individual component in the `Visual Studio` installer
1. via using the `Windows 11 SDK (10.0.26100.0)` installer through the [Windows SDK installer website](https://developer.microsoft.com/windows/downloads/windows-sdk/)
1. via adding the [Microsoft.Windows.SDK.CPP](https://www.nuget.org/packages/Microsoft.Windows.SDK.CPP/) 
packages to your Visual Studio project via Nuget.

> [!Important]
> The VBS Enclave SDK automatically includes Microsoft.Windows.SDK.CPP version 10.0.26100.7463
> as a dependency, providing access to the latest user binding APIs without additional configuration.

##### Repository

*The code generator uses Google Flatbuffers to facilite marshaling data into and out of the enclave.
This means we take Flatbuffers as a dependency, specifically in our `ToolingSharedLibrary` project.
We use [vcpkg](https://learn.microsoft.com/vcpkg/get_started/overview) to add the flatbuffer compiler 
and header files into our nuget package. To build the repository you will need to install/integrate 
`vcpkg` into your visual studio application.*

Here are the instructions to integrate vcpkg into your visual studio application:

https://learn.microsoft.com/vcpkg/get_started/get-started-msbuild?pivots=shell-powershell

You only need to follow step 1 (Set up vcpkg) in the above link, then close and relaunch visual studio. 
After this, you should be able to build the entire repository without issue. See the build instructions below.

### Build instructions.
The projects in this repository support only x64 and arm64 builds. 

- In a PowerShell window run the `buildScripts\build.ps1` script. This will build the `CodeGenerator` and `SDK` nuget packages.
Once this is complete the `CodeGenerator` and `SDK` nuget packages can be found in the `_build` folder in the root of the repository.

CodeGenerator and SDK consumption via nuget
------------
1. packages: [Microsoft.Windows.VbsEnclave.CodeGenerator](https://www.nuget.org/packages/Microsoft.Windows.VbsEnclave.CodeGenerator) 
and [Microsoft.Windows.VbsEnclave.SDK](https://www.nuget.org/packages/Microsoft.Windows.VBSEnclave.SDK).
1. Install them both your into **enclave** project and your **hostApp** project. 
   
In your **enclave** projects .vcxproj or .props file add the following:
```xml
<PropertyGroup>
    <VbsEnclaveVirtualTrustLayer>Enclave</VbsEnclaveVirtualTrustLayer>
    <VbsEnclaveEdlPath>Absolute-Path-To-Your-.Edl-File</VbsEnclaveEdlPath>
    <VbsEnclaveNamespace>Namespace-for-the-generated-code</VbsEnclaveNamespace>
    
    <!-- Optional properties -->
        
    <VbsEnclaveGeneratedFilesDir>directory-to-output-generated-files</VbsEnclaveGeneratedFilesDir>
    
    <!-- Only needed if you are importing other .edl files -->
    <VbsEnclaveImportDirectories>paths-to-directories-containing-.edl-files</VbsEnclaveImportDirectories>

    <!-- Only needed if you want to consume the Veil C++ support library in your enclave. -->
    <VbsEnclaveConsumeCppSupportLib>true</VbsEnclaveConsumeCppSupportLib>
</PropertyGroup>
```

 This will kick off the code generation and ingest the SDK inside your **enclave** project at build time.

In your **hostApp** projects .vcxproj or .props file add the following:
```xml
<PropertyGroup>
    <VbsEnclaveVirtualTrustLayer>HostApp</VbsEnclaveVirtualTrustLayer>
    <VbsEnclaveEdlPath>Absolute-Path-To-Your-.Edl-File</VbsEnclaveEdlPath>
    <VbsEnclaveNamespace>Namespace-for-the-generated-code</VbsEnclaveNamespace>
    <VbsEnclaveVtl0ClassName>Encapsulated-classname-for-your-enclave</VbsEnclaveVtl0ClassName>

     <!-- Optional properties -->
        
    <VbsEnclaveGeneratedFilesDir>directory-to-output-generated-files</VbsEnclaveGeneratedFilesDir>
    
    <!-- Only needed if you are importing other .edl files -->
    <VbsEnclaveImportDirectories>paths-to-directories-containing-.edl-files</VbsEnclaveImportDirectories>
</PropertyGroup>
```

This will kick off the code generation and ingest the SDK inside your **hostApp** project at build time.

*Note* : Be sure to update the `<VbsEnclaveEdlPath>`, `<VbsEnclaveNamespace>`, `<VbsEnclaveVtl0ClassName>`
and `<VbsEnclaveImportDirectories>` properties with valid values.

Also see the docs on the `.edl` format and `CodeGeneration` [here](./docs/Edl.md) and [here](./docs/CodeGeneration.md)
for more information on them.

*Note* : The `CodeGenerator` nuget package can be used without the `SDK` nuget package
   and the `SDK` nuget package can also be used without the `CodeGenerator` nuget package. They do not rely on each other.

### Strict memory access
Strict memory access (see [EnclaveRestrictContainingProcessAccess](https://learn.microsoft.com/windows/win32/api/winenclaveapi/nf-winenclaveapi-enclaverestrictcontainingprocessaccess)),
when enabled, is a security feature that prevents the enclave from referencing VTL0 memory.

> [!Important]
> - Strict memory access is enabled by default for `release` builds to ensure that the enclave cannot reference VTL0 
memory.
> - Strict memory access is currently disabled for `debug` builds to work around a vertdll.dll memory access issue.
> - To disable strict memory access for development purposes, you can define a the preprocessor directive
> ```ENABLE_ENCLAVE_RESTRICT_CONTAINING_PROCESS_ACCESS=false``` in your project file.

### Consuming CodeGen/SDK in static libs for enclave DLLs

This is for those developers who don't want to put their business logic into the enclave dll project directly,
but instead want to put it into a static library that will be consumed by the enclave dll project.

#### SDK consumption

- Add the `<VbsEnclaveVirtualTrustLayer>Enclave</VbsEnclaveVirtualTrustLayer>` property to your enclave dll project if 
not already set. This will make sure the `LinkerPragmas.veil_abi.cpp` file from the SDK package is added to your dll
project at build time.
- Note: adding this property will also add the `veil_enclave_lib.lib` static library to your enclave dll project which 
contains the functions to be exported by the dll.
- You should be able to build your enclave dll project without issue after this. In a VS developer powershell window
you can confirm the exports are present by using the `dumpbin /exports <path-to-enclave-dll>` command.

#### Codegen consumption

- At build time, your enclave dll will need to consume the `LinkerPragmas.<name-of-your-.edl-file>.cpp` file that was 
generated in your static library projects `Generated Files\VbsEnclave\Enclave\Abi` folder.
- This is so that generated export functions that live in the static lib can be exported from your enclave dll.
- You should be able to build your enclave dll project without issue after this. In a VS developer powershell 
window you can confirm the exports are present by using the `dumpbin /exports <path-to-enclave-dll>` command.

> [!Tip]
> - Include the `LinkerPragmas.<edl-file-name>.cpp` file in your enclave dll build via a `.targets` file that adds it 
before the `ClCompile` target runs.
> - Doing it this way will ensure that the generated file is always included in the build without you having to 
explicitly add it to your dll project.

Here is an example target that you can add to a `.targets` file that is consumed by your enclave dll project:
```xml
<Target Name="AddVbsEnclaveCodegenExportToBuild" BeforeTargets="ClCompile">
    <ItemGroup>
        <ClCompile Include="Some\Path\To\Your\LinkerPragmas.<name-of-your-.edl-file>.cpp">
            <!-- Example incase you use precompiled headers. This file does not contain any #include statements. -->
            <PrecompiledHeader>NotUsing</PrecompiledHeader>
        </ClCompile>
    </ItemGroup>
</Target>
```

Vbs enclave implementation library (veil) usage
------------
Currently the SDK is located inside a separate solution file called `vbs_enclave_implementation_library.sln` 
located in `./src/VbsEnclaveSDK`.

To view the code for the SDK Launch and build the solution. For further information on building and interacting
with the SDK you can view the SDK specific README file [here](./src/VbsEnclaveSDK/README.md).

Samples
------------

You can view our sample app that uses both the `CodeGenerator` and `SDK` nuget packages in the `SampleApps` solution
[here](./SampleApps/SampleApps/README.md).

General Information
------------

Each project should have their own `README.md` file so you should read those
before changing anything. They might contain more information specific to the project.

Contributing
------------

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

Trademarks
------------
This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
