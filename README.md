VBS enclave tooling
================

Introduction
------------
Coming soon.

Official Nuget packages
------------
`There are currently no official nuget packages for the vbs enclaves tooling project.`
An official package will be added to nuget.org closer to our release date. See the 
`Building locally` section for how you can use the tool before then.

Building locally
------------

#### Prerequistes

*The code generator uses Google Flatbuffers to facilite marshaling data into and out of the enclave.
This means we take Flatbuffers as a dependency, specifically in our `ToolingSharedLibrary` project.
We use [vcpkg](https://learn.microsoft.com/en-us/vcpkg/get_started/overview) to add the flatbuffer compiler and header files into our nuget package. To build the
repository you will need to install/integrate `vcpkg` into your visual studio application inorder 
to build this repository.*

Here are the instructions to integrate vcpkg into your visual studio application:

https://learn.microsoft.com/vcpkg/get_started/get-started-msbuild?pivots=shell-powershell

You only need to follow step 1 (Set up vcpkg) in the above link, then close and relaunch visual studio. 
After this, you should be able to build the entire repository without issue. See the build instructions below.

#### Build instructions.
The projects in this repository support only x64 and arm64 builds. 

- To build the `VbsEnclaveTooling` executable on its own build the `ToolingExecutable` project
- To build the VbsEnclaveTooling executable and also generate the `VbsEnclaveTooling` .nupkg file 
  that can be added to your project there are two ways.
  1. Build the `ToolingNuget` project in Visual Studio. This will generate a .nupkg
     file in the `_build` directory and output the executable in `_build\$(platform)\$(configuration)`.
  1. `OR` in a Visual Studio developer Powershell window run the `buildScripts\build.ps1` 
     script. This will do the same as above.

For F5 debugging VbsEnclaveTooling.exe locally, [see the ToolingExecutable projects instructions here](./src/ToolingExecutable/README.md)


Using VbsEnclaveTooling.exe from within your own Visual Studio project to generate code
------------

Once you have built the nuget package, you can add it directly to your own visual studio
project by doing the following:

1. Right click your project > Manage Nuget Packages... > click the gear icon on the top right
   of the page and add `<path-to-cloned-VbsEnclaveTooling-repo>\_build` as a package source and click ok.
1. Switch the package source in the dropdown on the top right of the page to
   your new package source that points to the location above.
1. You should now see the `VbsEnclaveTooling` nuget package show up in the browse list.
1. Install it in your enclave project and your hostApp project.
1. In your enclave projects .vcxproj file add the following inside a `<PropertyGroup>` attribute
   `<VbsEnclaveEdlPath>Path-To-Your-.Edl-File</VbsEnclaveEdlPath>`

*Note*: A new VbsEnclaveTooling .nupkg file is generated everytime you build the `ToolingNuget`
project. It will appear as `Microsoft.Windows.VbsEnclaveTooling.0.0.0.nupkg` in the `_build` file.

If you already have it installed into your project, you will need to uninstall and reinstall it
via the "Manage Nuget Packages" window/refresh the page. 

This is helpful when you need to test changes made in the `ToolingExecutable`
or the `ToolingSharedLibrary` projects inside a project that consumes the nuget package.

VbsEnclaveSDK usage
------------
Currently the SDK is located inside a separate solution file called `vbs_enclave_implementation_library.sln` 
located in `./src/VbsEnclaveSDK`.

To view and load the SDK Launch and build the solution. For further information on building and interacting
with the SDK you can view the SDK specific README file [here](./src/VbsEnclaveSDK/README.md).

The SDK also contains a sample hostApp and sample enclave project where you can view how a developer interacts
with the SDK.

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
