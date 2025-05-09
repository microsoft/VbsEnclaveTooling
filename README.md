VBS enclave tooling
================

The VBS enclave tooling repository provides both a `CodeGenerator` and an `SDK` nuget package to make developing
features that interact with a VBS enclave easier. To learn more about VBS enclaves you can view the official documentation 
[here](https://learn.microsoft.com/windows/win32/trusted-execution/vbs-enclaves).

#### Language support for CodeGenerator and SDK
| Language          | Supported |
|-------------------|-----------|
| C++ (20 or later) |    ✅     |
| Rust              |    ❌     |


Building locally
------------

### Prerequistes

##### Operating System

| OS                  | Build               |
|---------------------|---------------------|
| Windows 11          | 26100.2314 or later |
| Windows Server 2025 | All                 |

##### Build system
| IDE                   | Build engine |
|-----------------------|--------------|
| Visual Studio 2022 17 | msbuild      |

##### Repository

*The code generator uses Google Flatbuffers to facilite marshaling data into and out of the enclave.
This means we take Flatbuffers as a dependency, specifically in our `ToolingSharedLibrary` project.
We use [vcpkg](https://learn.microsoft.com/vcpkg/get_started/overview) to add the flatbuffer compiler and header files into our nuget package. To build the
repository you will need to install/integrate `vcpkg` into your visual studio application.*

Here are the instructions to integrate vcpkg into your visual studio application:

https://learn.microsoft.com/vcpkg/get_started/get-started-msbuild?pivots=shell-powershell

You only need to follow step 1 (Set up vcpkg) in the above link, then close and relaunch visual studio. 
After this, you should be able to build the entire repository without issue. See the build instructions below.

### Build instructions.
The projects in this repository support only x64 and arm64 builds. 

- In a PowerShell window run the `buildScripts\build.ps1` script. This will build the `CodeGenerator` and `SDK` nuget packages.
Once this is complete the `CodeGenerator` and `SDK` nuget packages can be found in the `_build` folder in the root of the repository.

CodeGenerator and SDK consumption
------------
Once you have built (or downloaded) the `CodeGenerator` and `SDK` nuget packages, you can add them directly to your own visual studio
project by doing the following:

1. Right click your project > Manage Nuget Packages... > click the gear icon on the top right
   of the page and add `<path-to-cloned-VbsEnclaveTooling-repo>\_build` as a package source and click ok.
1. Switch the package source in the dropdown on the top right of the page to
   your new package source that points to the location above.
1. You should now see the `Microsoft.Windows.VbsEnclave.Codegenerator` and the `Microsoft.Windows.VbsEnclave.SDK` nuget packages show up in the browse list.
1. Install them both your into **enclave** project and your **hostApp** project. 
   
In your **enclave** projects .vcxproj or .props file add the following:
```xml
<PropertyGroup>
    <VbsEnclaveVirtualTrustLayer>Enclave</VbsEnclaveVirtualTrustLayer>
    <VbsEnclaveEdlPath>Absolute-Path-To-Your-.Edl-File</VbsEnclaveEdlPath>
    <VbsEnclaveNamespace>Namespace-for-the-generated-code</VbsEnclaveNamespace>
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
</PropertyGroup>
```

This will kick off the code generation and ingest the SDK inside your **hostApp** project at build time.

*Note* : Be sure to update the `<VbsEnclaveEdlPath>`, `<Namespace>` and `<Vtl0ClassName>` properties with valid values.

Also see the docs on the `.edl` format and `CodeGeneration` [here](./docs/Edl.md) and [here](./docs/CodeGeneration.md) for more information on them.

*Note* : The `CodeGenerator` nuget package can be used without the `SDK` nuget package
   and the `SDK` nuget package can also be used without the `CodeGenerator` nuget package. They do not rely on each other.

### Strict memory access
Strict memory access (see [EnclaveRestrictContainingProcessAccess](https://learn.microsoft.com/windows/win32/api/winenclaveapi/nf-winenclaveapi-enclaverestrictcontainingprocessaccess)), when enabled, is a security feature that prevents the enclave from referencing VTL0 memory.

It must be enabled for 'release' builds.

*Note* : Strict memory access is currently disabled for 'debug' builds to work around a vertdll.dll memory access issue.

*Note* : To disable strict memory access for development purposes, you can define a the preprocessor directive ```ENABLE_ENCLAVE_RESTRICT_CONTAINING_PROCESS_ACCESS=false``` in your project file.


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
