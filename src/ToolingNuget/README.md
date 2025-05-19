ToolingNuget
================

Creating a nuget package file (.nupkg)
------------
When this project builds it uses the `ToolingExecutable` project
to generate a nuget package that other projects can consume. 
The nuget package will contain a few things:

1. The `edlcodegen.exe` file that will be used to generate
   code that will marshal data into and out of an enclave.
1. The `Microsoft.Windows.VbsEnclave.CodeGenerator.props` and `Microsoft.Windows.VbsEnclave.CodeGenerator.targets`
   files.
1. The Flatbuffer compiler (`Flatc.exe`)
1. The `veil_cpp_support` static library for C++ support (limited subset)


**Note:** You may need to rebuild the project when you have made updates
        to the `Microsoft.Windows.VbsEnclave.CodeGenerator.targets/props` files,
        the nuspec file, or the powershell scripts to get Visual Studio
        to see those changes.
