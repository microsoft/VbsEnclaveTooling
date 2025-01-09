ToolingNuget
================

Creating a nuget package file (.nupkg)
------------
When this project builds it uses the `ToolingExecutable` and the
`VbsEnclaveSDK` projects to generate a nuget package that other
projects can consume. The nuget package will contain a few things

1. The `VbsEnclaveTooling.exe` file that will be used to generate
   code that will marshal data to and from an enclave.
1. The `VbsEnclaveSDK` projects source files to be
   built by the project that consumes it at build time via a targets
   file.
1. The `Microsoft.VbsEnclaveTooling.props` and `Microsoft.VbsEnclaveTooling.targets`
   files.


`Note:` You may need to rebuild the project when you have done updates
        to the `Microsoft.Windows.VbsEnclaveTooling.targets/props` files,
        the nuspec file, or the powershell scripts to get Visual Studio
        to see those changes.
