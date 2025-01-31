## VbsTooling CodeGen (Work in progress)

Currently the tooling supports hostApp to enclave code generation, although there is still more work to be done.  The basic premise is to allow 
developers to call their functions that live in VTL1 in a natural way without having interact with the `CallEnclave` api and `void*` mechanics.
The generated code will package up their function parameters, copy them to vtl1 and and forward them to their vtl1 function without the developer needing to do 
any casting. Note: Currently only HostApp -> enclave calls are supported but enclave -> hostApp will also be supported before we release.

Here is how it works

1. Developer creates an .edl file like [see example edl here](../src/UnitTests/TestFiles/EnclaveFunctionsCodeGen.edl). For some background on
   our edl support see: [more on edl here](./Edl.md).
1. Developer Adds nuget package to both their enclave visual studio project and their hostapp visual studio project. 
   Following the `Using VbsEnclaveTooling.exe from within your own Visual Studio project to generate code` section
   in the root README.md file in the repository
1. When the developer builds their enclave and host projects the following artifacts will be generated in the directory they chose as their
   output directory:
   ```
    VbsEnclaveGenerated_<Name of edl file>_/
    |
    |--- Shared/
    |       |--- EnclaveDeveloperTypes.h
    |
    |--- Enclave/
    |       |--- ParameterVerifiers.h
    |       |--- <name-of-edl-file>.def
    |       |--- VTL1_Implementations.h
    |       |--- VTL1_Stubs.cpp
    |
    |--- HostApp/
            |--- VTL0_Stubs.h
   ```

Note: Currently the tool will generate all files regardless of whether you want only the parts necessary for the 
hostapp or parts necessary for the enclave. In the future we will update the tool to allow you to specify which
entity you want to generate files for (hostapp or enclave).

1. For the Host app project only the `Shared` folder and the `HostApp` folder need to be included.
1. For the enclave project only the `Shared` folder and the `Enclave` folder need to be included.

- `EnclaveDeveloperTypes.h` - This contains all the types the developer provided within the .edl file.
- `ParameterVerifiers.h`  - This contains per function code to copy and verify function parameters from vtl0 to vtl1 (still a work in progress)
- `<name-of-edl-file>.def`  - A module definition file that contains all generated stub functions the vbs enclave abi uses to call the developers impl function in vtl1
- `VTL1_Implementations.h` - This contains all of the generated developer VTL1 impl function declarations (Developer must implement them). It also contain the ABI impl functions used to call into the developers impl function from the ABI.
- `VTL1_Stubs.cpp` - This contains all of the generated VTL1 stub functions that will be exported by the enclave. The ABI will call into these functions from the hostApp inorder to eventually call into the developers impl function.
- `VTL0_Stubs.h` - This contains a class that takes an void* to an enclave instance at construction time. The class contains stub functions that the developer will use in the hostApp to call their impl function in vtl1. 

Note: The class is tied to the enclave dll in the sense that the stubs within it use the `void*` and the name of the stub function in vtl1 to call into the abi layer.
If the void* was null or a different enclave the call would fail. Unless of course that enclave exports a function with the same name and parameters. It is up to
the developer to provide the correct enclave instance to the class.

### ABI layer

The tooling nuget package exports 4 header files that the above files rely on to call an enclave function from the hostApp:
1. `HostHelpers` - Contains code that the vtl0 class stub functions will call into to initiate a call to the developers impl function in vtl1
1. `EnclaveHelpers.h` - Contains code used to bridge the gap between the vtl0 stub function call and the call to its vtl1 impl function. This file lives in Vtl1. The developers enclave project should contain a macro called `__ENCLAVE_PROJECT__` inorder for the contents of this file to be available.
1. `VbsEnclaveAbiBase.h` - Contains the base structures and parameter forwarding functions needed by both sides (hostApp and enclave) so the correct parameters and correct vtl1 impl functions are called. This closes the gap between the ABI and the developers impl vtl1 function.
1. `VbsEnclaveMemoryHelpers.h` - Contains smart pointers and memory accessors needed to copy data into and out of the enclave. (Still a work in progress).

These can be accessed via:
```
#include <VbsEnclaveABI\Shared\VbsEnclaveAbiBase.h>
#include <VbsEnclaveABI\Shared\VbsEnclaveMemoryHelpers.h>
#include <VbsEnclaveABI\Enclave\EnclaveHelpers.h>
#include <VbsEnclaveABI\Host\HostHelpers.h>
```

### Data flow

1. Developer creates enclave instance then creates enclave class e.g `auto enclave_class = GeneratedEnclaveClass(enclave_instance);`
2. Developer calls vtl0 abi with enclave instance and function name e.g `vtl0_memory_ptr<User> user { enclave_class.GetUser("Bob") } ;`
3. Abi packages parameters into a struct that contains a tuple type specific for that function. The structure also contains a buffer and size for a return result and a function pointer to allow the abi to allocate memory on demand during the function call.
1. The structure is then casted to a void* and then calls `CallEnclave` with this structure as input. 
1. The Abi layer once in the enclave has its code within a try/catch, and only returns HRESULTs as void*. Note: the plan is to support error codes and throwing on both sides, but right now only throwing is available outside the CallEnclave boundary.
1. The Abi then copies the void* input into an internal vtl1 structure then casts the copied parameter data into a vtl1 tuple and fowards the parameters to the vtl1 abi impl function.
1. The abi impl function then calls the developers impl function with the correct parameters.
1. Upon return (still in vtl1) from the developers impl function, if the function returns a value, this value is serialized into an array of bytes and copied into the original structures return buffer along with its size. Note the buffer size is allocated using the allocation function pointer in the original structure.
1. When the abi returns from vtl1 if there is a return value it is deserialized and returned back to the caller.


Note: since return values are created from the heap using heap alloc, the developer will need to use the `vtl0_memory_ptr` smart pointer or use `HeapFree` themselves for any returned object from vtl1.

### Things still missing
1. Code needs to be added to developers can pass in an std::string to the vtl0 stub and have the characters copied then passed as a new std::string in vtl1
1. For InOut parameters code needs to be added just like in the return value case where we copy data from vtl1 back into vtl0. Currently InOut parameters are
basically just In parameters.
1. For out parameters to work nicely we should allow vtl1 to use vtl1 memory only. Then upon return from the vtl1 impl function perform a copy of the data 
in the second pointer. Note: Out params will always have two pointers e.g _Out_ mytype**. This means we need to send a vtl1 only copy of both pointers to the
vtl1 function. Then in the ABI layer copy the data back into the vtl0 verson of the out param.
1. Enclave to host app codegen.
                          
### How the generated ABI code looks (spacing updated for clarity)

`Generated enclave C++ class with stub function`
```C++
namespace VbsEnclaveGenerated_test
{
    namespace HostApp
    {
        namespace VTL0_Stubs
        {
            struct testWrapper
            {

                testWrapper(LPVOID enclave) : m_enclave(enclave){}

                MyStruct1* TrustedGetStruct1(
                    _In_ MyStruct1 arg1,
                    _In_ std::array<MyStruct1, 5> arg2,
                    _Inout_ MyStruct1* arg3,
                    _Out_ MyStruct1** arg4)
                {
                    // Add function parameters tuple
                    ParameterContainer<
                        FunctionParameter<MyStruct1>,
                        FunctionParameter<std::array<MyStruct1, 5>>,
                        FunctionParameter<MyStruct1*>,
                        FunctionParameter<MyStruct1**>> parameters ( 
                                FunctionParameter<MyStruct1>{ arg1 },
                                FunctionParameter<std::array<MyStruct1, 5>>{ arg2 },
                                FunctionParameter<MyStruct1*>{ arg3 },
                                FunctionParameter<MyStruct1**>{ arg4 } );

                    using FunctionParams = std::decay_t<decltype(parameters)>;

                    return CallVtl1StubWithResult<MyStruct1*, FunctionParams>(
                        m_enclave,
                        "TrustedGetStruct1_Generated_Stub",
                        parameters);
                }


            private:
                 LPVOID m_enclave{};
            };
        }
    }
}


```

`Generated VTL1 stub called by abi via functions in HostHelpers.h`
```C++
namespace VbsEnclaveGenerated_test
{
    namespace Enclave
    {
        namespace VTL1_Stubs
        {

            void* CALLBACK TrustedGetStruct1_Generated_Stub(void* function_context)
            {
                try
                {
                    HRESULT __hr = ([&]() noexcept
                        {
                            // Create parameter tuple type
                            using FunctionParams = ParameterContainer<
                                FunctionParameter<MyStruct1>,
                                FunctionParameter<std::array<MyStruct1, 5>>,
                                FunctionParameter<MyStruct1*>,
                                FunctionParameter<MyStruct1**>>;

                            // Pass void* function context, parameters, developer impl function
                            // and a parameter verifier function to the CallEnclaveFunction abi function
                            THROW_IF_FAILED((CallEnclaveFunctionWithResult<MyStruct1, FunctionParams>(
                                function_context,
                                VTL1_Implementations::AbiDefinitions::TrustedGetStruct1_Abi_Impl,
                                ParameterVerifiers::CopyAndVerifyFor_TrustedGetStruct1<FunctionParams>)));

                            return S_OK;
                        }
                    )();
                    LOG_IF_FAILED(__hr);
                    RETURN_HR_AS_PVOID(__hr);
                }
                catch (...)
                {
                    HRESULT __hr = wil::ResultFromCaughtException();
                    LOG_IF_FAILED(__hr);
                    RETURN_HR_AS_PVOID(__hr);
                }
            }
        }
    }
}
```

`Generated VTL1 abi impl and developer function declaratios.
Calls initiated by functions in VbsEnclaveEnclaveHelpers.h and then the parameter forwarding functions of VbsEnclaveAbiBase.h`
```C++
namespace VbsEnclaveGenerated_test
{
    namespace Enclave
    {
        namespace VTL1_Implementations
        {
            namespace DeveloperDeclarations
            {
                // Implementation declaration for Developer function. The Developer must implement this 
                // function
                MyStruct1 TrustedGetStruct1(
                    _In_ MyStruct1 arg1,
                    _In_ std::array<MyStruct1, 5> arg2,
                    _Inout_ MyStruct1* arg3,
                    _Out_ MyStruct1** arg4);
            }

            namespace AbiDefinitions
            {

                // Abi impl function that forwards parameters to developers impl function declaration.
                static inline MyStruct1 TrustedGetStruct1_Abi_Impl(
                    _In_ MyStruct1 arg1,
                    _In_ std::array<MyStruct1, 5> arg2,
                    _Inout_ MyStruct1* arg3,
                    _Out_ MyStruct1** arg4)
                {
                    return VTL1_Implementations::DeveloperDeclarations::TrustedGetStruct1(arg1,arg2,arg3,arg4);
                }
            }
        }
    }
}
```
