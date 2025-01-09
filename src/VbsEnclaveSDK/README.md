VbsEnclaveSDK
================

Introduction
------------
This project contains all the source code related to the SDK.
These source files will be added to the developers project once
they add the `VbsEnclaveTooling` nuget package. This will allow the
developer to control whether they want to compile the CRT the
SDK uses with /MT, /MTd, /MD or /MDd.

See the `Microsoft.Windows.VbsEnclaveTooling.targets` file which
is invoked during build time. It contains the target that is used
to build include the SDK header files and C/C++ files to be consumed
by another project.

Developer loop:
1. Following the repositories `README.md` file in the root folder.
1. In your `HostApp` project and `Enclave` project you should now
   be able to use the SDK header files in the `VbsEnclaveSDK\Includes`
   folder of of this project. 
1. You can also now build both either project. During the build
   Visual Studio will build the `VbsEnclaveSDK\Sources` files directly 
   into the the project. 


### Note 1:
Your enclave project will receive CRT errors if C++ is
is enabled. This is a work in progress as we'll need to
provide stub functions for functionality not supported
by enclaves. For now, the SDK is in C so the end-to-end
scenario can be tested.

### Note 2:
The path `VbsEnclaveSDK\*` matter during build time. If
you decide to change this folder name and its contents
be sure to also change the `.nuspec` file in the `ToolingNuget`
project as well as the `VbsEnclaveSDK` targets located
in the `Microsoft.Windows.VbsEnclaveTooling.targets` file.

### Note 3:
The C/C++ files don't use a precompiled header so there will
be an error if a project uses them that is consuming the SDK.
This will/can be fixed before release as the SDK gets fleshed
out. In the mean time you can use the `Not Using Precompiled Headers`
option in your projects properties. Specifically in the
C/C++ > precompiled headers section before consuming the SDK.
