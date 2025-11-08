Vbs Enclave Implementation Library
================

Supported Languages
------------
1. C++ (20 and above)

Introduction
------------
*Note* `veil` stands for "Vbs Enclave Implementation Library"

This solution contains all the source code related to the veil SDK. The SDK
produces a 3 static libraries one for the hostApp, one for the enclave and
one for C++ support within an enclave. These are called `veil_host_lib` ,
`veil_enclave_lib` and `veil_enclave_cpp_support_lib` respectively. 

The `veil_nuget` project is used to build and create the
`Microsoft.Windows.VbsEnclave.SDK` nuget package. To build this solution
you must first build the `VbsEnclaveTooling` solution in the root of the
repository. This will 
generate the `Microsoft.Windows.VbsEnclave.CodeGenerator` nuget package that
the SDK needs to consume. Once that is done you will only need to build this solution.
when needing to build the SDK nuget package.

You can view the SDK's usage patterns in
the `SampleApps` solution [here](https://github.com/microsoft/VbsEnclaveTooling/tree/main/SampleApps/SampleApps)

Consuming the SDK nuget package
------------
Once the nuget package is built you can consume the `.nupkg` file that is generated
in the `VbsEnclaveSdk\_build` folder inside your hostApp or enclave project.

In a `<PropertyGroup />` in your *enclave* projects .vcxproj or .props file use:
`<VbsEnclaveVirtualTrustLayer>Enclave</VbsEnclaveVirtualTrustLayer>`

- This will add the `veil_enclave_lib.lib` static lib to your enclaves dll at build time.

> [!Note]
> If you wish to add the `veil_enclave_cpp_support_lib.lib` static lib to your enclaves build add `<VbsEnclaveConsumeCppSupportLib>true</VbsEnclaveConsumeCppSupportLib>` to a `<PropertyGroup />` in your projects `.vcxproj` or `.props` file.


In a `<PropertyGroup />` your *hostApp* projects .vcxproj or .props file use:
`<VbsEnclaveVirtualTrustLayer>HostApp</VbsEnclaveVirtualTrustLayer>`

- This will add the `veil_host_lib` static lib to your hostApps dll at build time. 

Supported features
------------
1. "Taskpool" support for the enclave by the HostApp. The enclave can now queue work onto vtl0 threads easily using veil::future/veil::promise behavior.
1. Bcrypt wrapper methods to make encryption/decryption code easier to write.
