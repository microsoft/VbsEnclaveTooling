ToolingExecutable
================

Running via Visual Studio F5/local debugging
------------
The ToolingExecutable project is set up as a regular executable project. To pass
arguments to the exe do the following:

1. Set `ToolingExecutable` as a `Startup project` if not done already.
1. Right click the `ToolingExecutable` project and select "Properties" at the bottom of the flyout.
1. Navigate to the `Debugging` section under `Configuration Properties` and set the following properties:
1. Command: `$(TargetPath)`
1. Command Arguments: This should have the arguments you want to pass to `ToolingExecutable`.
   1. e.g `"--Language" "C++" "--EdlPath" "C:\Users\Public\Documents\test.edl" "--ErrorHandling" "ErrorCode" "--OutputDirectory" "C:\Users\Public\Documents" "--VirtualTrustLayer" "HostApp" "--Vtl0ClassName" "MyEnclaveClass" "--Namespace" "MyGeneratedNamespace" "--FlatbuffersCompilerPath" "C:\Users\Public\Documents\flatbuffers\flatc.exe"`

1. Working Directory: `$(ProjectDir)`

### Note 1:
The `--OutputDirectory` argument defaults to the current working directory if not provided.

### Note 2:
The `--VirtualTrustLayer` argument will change what files are produced. E.g if the `HostApp` argument
is used then only files that are usable by a hostApp project will be generated. If the `Enclave`
argument is used, then only files that are usable by an enclave project are generated.

### Note 3:
The `--Vtl0ClassName` and `--Namespace` arguments are optional. If they are not provided then the
default namespace for the generated code will be the name of the `.edl` file and the name of the 
generated vtl0 class will be `<Name of edl file>Wrapper`.

### Note 4:
The `--FlatbuffersCompilerPath` argument is optional. If it is not provided then the location the executable is ran from
will be used as the path.

*Note: This project consumes the `ToolingSharedLibrary` project which uses the Google flatbuffers vcpkg
static package inorder to facilite marshaling data into and out of the enclave. This means we must take 
it as a dependency, and you must install/integrate vcpkg into your visual studio inorder to build the project.*

Here are the instructions to integrate vcpkg into your visual studio application:

https://learn.microsoft.com/vcpkg/get_started/get-started-msbuild?pivots=shell-powershell

You only need to follow step 1 (Set up vcpkg) in the above link, then close and relaunch Visual Studio. After this
you should be able to build the entire repository without issue.
