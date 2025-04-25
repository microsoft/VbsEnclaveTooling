VbsEnclaveSDK
================

Introduction
------------
This project contains all the source code related to the SDK. The SDK
produces a static library for the hostApp and one for the enclave. 
`veil_host_lib` and `veil_enclave_lib` respectively.

This is still being fleshed out but you can view the usage patterns in both
the `sample_enclave` and `sample_hostapp` projects. Note about building
the sample enclave project locally. You can follow the instructions here: 
[Signing VBS enclave DLLs](https://learn.microsoft.com/windows/win32/trusted-execution/vbs-enclaves-dev-guide#step-3-signing-vbs-enclave-dlls),
to create a certificate for your enclave. Then you can edit the `EnclaveCertName`
property within the `sample_enclave` vcxproj file located here
in the [sample_enclave.vcxproj](https://github.com/microsoft/VbsEnclaveTooling/blob/8179c372186bd7ab1f1d68ac044fe4a98ccc7eef/src/VbsEnclaveSDK/samples/sample_enclave/sample_enclave.vcxproj#L54)
with the name of your signing certificate.

Currently supported features:
1. "Taskpool" support for the enclave by the HostApp. The enclave can now queue work onto vtl0 threads easily using std::future/std::promise behavior.
   See TaskPool sample [here](./samples/sample_hostapp/sample_taskpool.cpp)

Consumption
------------
Your enclave must export VeilEnclaveSdkEntrypoint, which is
a required entrypoint for the Veil Enclave SDK to function.
