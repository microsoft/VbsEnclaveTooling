## VbsTooling CodeGen (Work in progress)

The basic premise of our code generation is to allow developers to call their functions that live in either VTL1 or VTL0 in a natural way without having interact with the `CallEnclave` api and `void*` mechanics.
The generated code will package up your function parameters, copy them into and out of either VTL0 and VTL1, then forward them to their the your implementation function. The developer can then focus on their
on their business logic instead of the logic around the trust boundary.

### Here is how it works

1. Developer creates an .edl file like [see example edl here](../src/UnitTests/TestFiles/EnclaveFunctionsCodeGen.edl). For some background on
   our edl support see: [more on edl here](./Edl.md).
1. Developer Adds nuget package to both their enclave visual studio project and their hostapp visual studio project. 
   Following the `Using VbsEnclaveTooling.exe from within your own Visual Studio project to generate code` section
   in the root README.md file in the repository
1. When the developer builds their project and uses the `Enclave` string in the `<VbsEnclaveVirtualTrustLayer />` attribute in their `vcxproj/.props/.targets`
   file the following artifacts will be generated in the directory they chose as their output directory:
   ```
    VbsEnclave/
    |
    |--- Enclave/
    |       |--- vbsenclave.def
    |       |--- Implementations.h
    |       |--- Stubs.cpp
    |       |--- DeveloperTypes.h
   ```
1. When the developer builds their project and uses the `HostApp` string in the `<VbsEnclaveVirtualTrustLayer />` attribute in their `vcxproj/.props/.targets`
   file the following artifacts will be generated in the directory they chose as their output directory:
   ```
    VbsEnclave/
    |
    |--- HostApp/
            |--- Stubs.h
            |--- DeveloperTypes.h

   ```

   `Note 1:` The default output directory when using the nuget package is `$(ProjectDir)\Generated Files`
   `Note 2:` During build time the files will automatically be added to the projects build so there is no need to explicitly include them.

### Files Generated
#### Generated for both Enclave and HostApp projects

- `DeveloperTypes.h`  - This contains all the types the developer provided within the .edl file.

#### Generated only for Enclave project

- `vbsenclave.def`    - A module definition file that contains all generated stub functions the vbs enclave abi uses to call the developers impl function in vtl1
- `Implementations.h` - This contains all of the generated developer VTL1 impl function declarations that the developer outlined in the `Trusted` section of the edl file.
                        The developer must implement these. It also contains the ABI impl functions used to call into the developers impl function from the ABI.
                        If a developer adds functions to the `Untrusted` section of the edl file, then a subsequent static function with the word `callback` appended to the name will be
                        added to the file. A developer can use these generated functions to call into a callback function they implement in vtl0 (hostApp).
- `Stubs.cpp`         - This contains all of the generated VTL1 stub functions that will be exported by the enclave. The ABI will call into these functions from the hostApp inorder to
                        eventually call into the developers impl function in the enclave (vtl1). 

#### Generated only for HostApp project

- `Stubs.h`           - This contains a class that takes a `void*` to an enclave instance at construction time. If the developer adds function declarations to the `Trusted` section of
                        the .edl file, then the class will contain abi stub functions that the developer will use in the hostApp to call their impl function in vtl1. The class also includes 
                        static function declarations that the developer must implement if they add function declarations to the `Untrusted` section in the .edl file.

`Note 3:` The class is tied to the enclave dll in the sense that the stubs within it use the `void*` and the name of the stub function in vtl1 to call into the abi layer.
If the void* was null or a different enclave the call would fail. Unless of course that enclave exports a function with the same name and parameters. It is up to
the developer to provide the correct enclave instance to the class.

### ABI layer

The tooling nuget package exports 6 header files that the above files rely on to call an enclave function from the hostApp or vice versa:

#### Shared by both Enclave and HostApp

1. `VbsEnclaveAbiBase.h` - Contains the base structures and parameter forwarding functions needed by both sides (hostApp and enclave) so the correct parameters and correct vtl1/vtl0 impl functions are called. This closes the gap between the ABI and the developers impl functions in vtl1 and vtl0.

#### Available only to Enclave when macro is set

1. `EnclaveHelpers.h` - Contains code used to bridge the gap between the vtl0 class function call and the call to its vtl1 impl function.
                        The file also contains code that will call a vtl0 class callback from vtl1.
1. `Vtl0Pointers.h` - Contains smart pointers that the abi used when dealing vtl0 memory.
1. `MemoryAllocation.h` - Contains code necessary to allocate vtl0 memory from vtl1.
1. `MemoryChecks.h.h` - Contains code necessary to check and verify vtl0 and vtl1 memory bounds.

`Note 4:` an enclave project must include a macro called `__ENCLAVE_PROJECT__` for the content of these files to be available to the project.

#### Available only to HostApp

1. `HostHelpers` - Similiar to `EnclaveHelpers.h` but for the vtl0 side. It contains code to forward parameters from a vtl0 class function to its impl in vtl1 and return its return value back to the originator.will call into to initiate a call to the developers impl function in vtl1. 
                   It also contains code to receive calls from vtl1 to be forwarded to a static impl function in the vtl0 generated enclave class.

#### How to access files

You typically won't ever need to interact with these files explicitly.
These can be accessed via:
```
#include <VbsEnclaveABI\Shared\VbsEnclaveAbiBase.h>
#include <VbsEnclaveABI\Enclave\EnclaveHelpers.h>
#include <VbsEnclaveABI\Shared\MemoryAllocation.h>
#include <VbsEnclaveABI\Shared\MemoryChecks.h>
#include <VbsEnclaveABI\Host\HostHelpers.h>
```

### Data flow HostApp -> Enclave (WIP)

### Data flow Enclave -> HostApp (WIP)


Note: since return values are created from the heap using heap alloc, the developer will need to use the `vtl0_memory_ptr` smart pointer or use `HeapFree` themselves for any returned object from vtl1.

### Things still missing
1. Deep copying of parameters needs to be added. This will be done when flatbuffers support is added.
1. _Out_ parameters in the .edl file that are pointers are currently generated as `T**`. When going
   from enclave -> hostApp there can be memory access violation exceptions since we need to allocate vtl0 memory
   for each pointer. Only then can we copy the vtl1 data into T*. This can be tricky so we will update this
   when we add flatbuffer support as we will no longer need the double pointers (we'll serialize the data to a blob
   then send it to vtl0).
1. Using smart pointers for InOut and Out parameters instead of raw pointers.
