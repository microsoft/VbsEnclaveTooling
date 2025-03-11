## VbsEnclaveTooling Code Geneneration

The basic premise of our code generation is to allow developers to call their functions that live in either VTL1 or
VTL0 in a natural way without having interact with the `CallEnclave` api and `void*` mechanics. The generated code
will package up your function parameters, copy them into and out of either VTL0 and VTL1, then forward them to their
the your implementation function. The developer can then focus on their on their business logic instead of the logic 
around the trust boundary. The invariant we will maintain is that parameters passed to a developers VTL0 function 
should contain only VTL0 memory, and parameters passed into a developers VTL1 function should only contain VTL1 memory.
To accomplish this our ABI layer will act in the middle between cross trust boundary calls, copying parameters into
VTL0/VTL1, passing only the copy with the correct memory type to the developers function.

### Here is how it works

1. Developer creates an .edl file like [example edl](../tests/EnclaveTests/CodeGenTestFunctions.edl).
   For some background on our edl support see: [more on edl here](./Edl.md).
1. Developer Adds nuget package to both their enclave visual studio project and their hostapp visual studio project. 
   Following the `Using VbsEnclaveTooling.exe from within your own Visual Studio project to generate code` section
   in the root README.md file in the repository
1. When the developer builds their project and uses the `Enclave` string in the `<VbsEnclaveVirtualTrustLayer />`
   attribute in their `vcxproj/.props/.targets` file the following artifacts will be generated in the directory they 
   chose as their output directory:
   ```
    VbsEnclave/
    |
    |--- Enclave/
    |       |--- vbsenclave.def
    |       |--- Implementations.h
    |       |--- Stubs.cpp
    |       |--- DeveloperTypes.h
   ```
1. When the developer builds their project and uses the `HostApp` string in the `<VbsEnclaveVirtualTrustLayer />`
   attribute in their `vcxproj/.props/.targets` file the following artifacts will be generated in the directory they 
   chose as their output directory:
   ```
    VbsEnclave/
    |
    |--- HostApp/
            |--- Stubs.h
            |--- DeveloperTypes.h

   ```

   `Note 1:` The default output directory when using the nuget package is `$(ProjectDir)\Generated Files`
   `Note 2:` During build time the files will automatically be added to the projects build so there is no need to
             explicitly include them.

### Files Generated
#### Generated for both Enclave and HostApp projects

- `DeveloperTypes.h`  - This contains all the types the developer provided within the .edl file.

#### Generated only for Enclave project

- `vbsenclave.def`    - A module definition file that contains all generated stub functions the vbs enclave abi uses
                        to call the developers impl function in vtl1
- `Implementations.h` - This contains all of the generated developer VTL1 impl function declarations that the
                        developer outlined in the `Trusted` section of the edl file. The developer must implement 
                        these. It also contains the ABI impl functions used to call into the developers impl function
                        from the ABI. If a developer adds functions to the `Untrusted` section of the edl file, then 
                        a subsequent static function with the word `callback` appended to the name will be added to
                        the file. A developer can use these generated functions to call into a callback function they
                        implement in vtl0 (hostApp).
- `Stubs.cpp`         - This contains all of the generated VTL1 stub functions that will be exported by the enclave.
                        The ABI will call into these functions from the hostApp inorder to eventually call into the 
                        developers impl function in the enclave (vtl1). 

#### Generated only for HostApp project

- `Stubs.h`           - This contains a class that takes a `void*` to an enclave instance at construction time. If the
                        developer adds function declarations to the `Trusted` section of the .edl file, then the class
                        will contain abi stub functions that the developer will use in the hostApp to call their impl 
                        function in vtl1. The class also includes static function declarations that the developer must 
                        implement if they add function declarations to the `Untrusted` section in the .edl file.

`Note 3:` The class is tied to the enclave dll in the sense that the stubs within it use the `void*` and the name of 
the stub function in vtl1 to call into the abi layer. If the void* was null or a different enclave the call would fail.
Unless of course that enclave exports a function with the same name and parameters. It is up to the developer to 
provide the correct enclave instance to the class.

### ABI layer

The tooling nuget package exports 6 header files that the above files rely on to call an enclave function from the 
hostApp or vice versa:

#### Shared by both Enclave and HostApp

1. `VbsEnclaveAbiBase.h` - Contains the base structures and parameter forwarding functions needed by both sides 
                           (hostApp and enclave) so the correct parameters and correct vtl1/vtl0 impl functions 
                           are called. This closes the gap between the ABI and the developers impl functions in 
                           vtl1 and vtl0.

#### Available only to Enclave when macro is set

1. `EnclaveHelpers.h`    -  Contains function that the generated abi functions will use when making calls into the enclave
                           (HostApp -> Enclave) and out of the enclave (Enclave -> HostApp). The functions in this 
                            file use the Win32 enclave accessor functions `EnclaveCopyOutOfEnclave` and 
                           `EnclaveCopyIntoEnclave`to copy data into and out of the enclave. 
                            Note: `CallVtl0CallbackFromVtl1` uses the `CallEnclave` Win32 api to call into a generated vtl0 callback
                            function which then forwards the function parameters to the developers vtl0 callback impl function.
                            See the `Enclave -> HostApp scenario` and `Call flow Enclave -> HostApp` below for more details.
1. `Vtl0Pointers.h`      - Contains smart pointers that the abi used when dealing vtl0 memory.
1. `MemoryAllocation.h`  - Contains code necessary to allocate vtl0 memory from vtl1.
1. `MemoryChecks.h.h`    - Contains code necessary to check and verify vtl0 and vtl1 memory bounds.

`Note 4:` an enclave project must include a preprocessor macro called `__ENCLAVE_PROJECT__` for the content of these files to be
          available to the project.

#### Available only to HostApp

1. `HostHelpers` - Similiar to `EnclaveHelpers.h` but for the vtl0 side. It contains functions to forward parameters from 
                   from the abi layer in vtl1 to a vtl0 function and return that functions return value back to vtl1.
                   It also handles the opposite case where a function in vtl1 is called from vtl0. In this case there is a
                   generated vtl0 function which is associated with the developers implementation of a `trusted` vtl1 
                   function.
                   Note: `CallVtl1ExportFromVtl0` uses the `CallEnclave` Win32 api to call into a generated vtl1 export
                   function which then forwards the function parameters to the developers vtl1 impl function.
                   See the `HostApp -> Enclave scenario` and `Call flow HostApp -> Enclave` below for more details.

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
### Generated code usage

for the following example we will assume the developer used the following .edl file content and the `VbsEnclaveTooling.exe`
executable generated code based on it.

```
// example edl
enclave {
    trusted {
        string TrustedExample(
            [out, count=int8_array_size] int8_t* int8_array,
            size_t int8_array_size
        );
    };

    untrusted {
        int32_t UntrustedExample(
            [in, out, size=blob_size] int8_t* int8_blob,
            size_t blob_size
        );
    };
};
```

Imagine the developer passes the string `MyEnclave` as the `Vtl0ClassName` argument and `VbsEnclave` as the 
`Namespace` argument to `VbsEnclaveTooling.exe` executable. The following sections describe what will be 
generated and how the developer will interact with the generated code.

#### HostApp -> Enclave scenario (trusted scope)

A class will be generated that will take in the enclaves `void*` in its constructor. This class contains
VTL0 versions for every function the developer declares in the `trusted` scope of the .edl file. See the
`Data flow HostApp -> Enclave` for the sequence of class that will happen when the developer invokes a
class method. This call is generated in the `Stubs.h` file in the `HostApp project`

The expectation is for a developer to use the generated class in the following way:
```C++
// This is in vtl0, in a developer function where they want to call their enclave trusted function.
// omitted Win32 code to create/initialize & load the enclave's void*, but imagine we have a void* variable we 
// called enclave_void_star after we created it.
MyEnclave generated_class = VbsEnclave::MyEnclave(enclave_void_star);
THROW_IF_FAILED(generated_class.RegisterVtl0Callbacks()); // call RegisterVtl0Callbacks at least once.
int8_t* int8_array = nullptr;

// Expected size of out parameter can be 0, if you expect the vtl1 callee to update this
// or if we know the value before hand we can add it in.
size_t variable_array_count {};

auto enclave_str = generated_class.TrustedExample(&int8_array, variable_array_count);
for(size_t i; i < variable_array_count; i++)
{
    // The abi layer should have done the work to copy the vtl1 data into our vtl0 array
    // Should print 0, 1, 2, 3, 4 ... up to 9
    std::cout <<  int8_array[i] << std::endl;
}

// Make sure int8_array and internal char array or EnclaveString are freed when function goes out of scope.
wil::unique_process_heap_ptr<int8_t> int8_array_ptr {int8_array};
wil::unique_process_heap_ptr<char> char_buffer_ptr {enclave_str.m_char_buffer};
std::cout <<  enclave_str.ToStdString() << std::endl;

```

`Note: 5` Regardless of whether or not a developer add functions to the 'trusted' or the 'untrusted' scopes in the .edl
file there will be a `RegisterVtl0Callbacks` function that is generated. This function will register the 
`AllocateVtl0MemoryCallback` and `DeallocateVtl0MemoryCallback` function to the vtl1 callback tabled. This
is needed for the ABI layer to function properly. So the `RegisterVtl0Callbacks` function must be called at
least once for the lifetime of then enclave before attempting to use the methods in the generated enclave class.

Back in the enclave a declaration for the enclave function would have been generated in the `Implementations.h` file.
The developer is expected to create a defintion for this declaration. Using the example .edl above the following 
declaration would be generated.

```C++
namespace VbsEnclave
{
    namespace VTL1_Declarations
    {
        EnclaveString TrustedExample(_Out_ std::int8_t** int8_array, _In_ size_t int8_array_size);
    }
}
```

`Note: 6` When the `out` annotation is used in tandom with a pointer, the code generator will generate both the
abi and the developer imple functions using a double pointer. This allows the standard pattern for the developer to
pass in the address of their pointer using `&<variable-name>` to the function like we see in the example above.

`Note: 7` Edl support both the `string` and `wstring` key words. When the former is used it is generated as a struct
with a `char*` and a `size_t` as fields. When the latter is used, it is generated as a struct with a `wchar_t*` and
a `size_t` as fields.

Continuing on, the developer could implement the declaration as follows:
```C++
EnclaveString VTL1_Declarations::TrustedExample(_Out_ std::int8_t** int8_array, _In_ size_t int8_array_size)
{
    *int8_array = nullptr;
    int8_array_size = 10;
    size_t array_size_in_bytes = sizeof(std::int8_t) * int8_array_size;
    std::vector<std::int8_t> int8_vector(int8_array_size);
    std::iota(int8_vector.begin(), int8_vector.end(), 0);

    // Abi provided function to allocate vtl1/vtl0 memory depending on which side of the trust boundary its called.
    // in this case it will allocate vtl1 memory.
    // The abi layer is responsible for freeing this memory and coping it into the vtl0 memory of the caller.
    *int8_array = reinterpret_cast<std::int8_t*>(AllocateMemory(array_size_in_bytes));
    memcpy_s(*int8_array, array_size_in_bytes, int8_vector.data(), array_size_in_bytes);

    // TODO: when deep copy of internal structs support is added, we shouldn't need to allocate vtl0 memory
    // directly, and should be able to allocate only vtl1 memory and have the abi layer take care of the conversion 
    // for us. So, the developer shouldn't need to use the 'EnclaveCopyOutOfEnclave' Win32 api directly.

    std::string return_from_enclave = "We returned this string from the enclave.";
    char * ret_char_array = nullptr;
    size_t str_size_in_bytes = sizeof(char) * return_from_enclave.size();

    // The abi layer catches exceptions, but the developer can catch them too.
    THROW_IF_FAILED(AllocateVtl0Memory(&ret_char_array, str_size_in_bytes));
    THROW_IF_NULL_ALLOC(ret_char_array);

    // free memory if the line below throws. vtl0_memory_ptr smart pointer is provided by the abi.
    vtl0_memory_ptr<char> str_mem_ptr { ret_char_array }; 
    THROW_IF_FAILED(EnclaveCopyOutOfEnclave(ret_char_array, return_from_enclave.data(), str_size_in_bytes));
    str_mem_ptr.release(); // vtl0 caller to free

    // Abi layer will handle copying the struct (not data of internal pointers, see note about deep copy support above)
    // to vtl0 memory.
    return EnclaveString { ret_char_array, str_size_in_bytes };

}
```

`Note: 8` As you can see in the code the developer writes, they never interact with the CallEnclave api, 
create a module.def file or even call into an exported function. This is all done by the abi layer. The  code
generator underhood generates export functions based on the declarations in the `trusted` scope and exports these
generated functions within the generated module.def file.

#### Enclave -> HostApp scenario (untrusted scope)

In the untrusted scenario, the function that the developer will implement is what we call a `callback`. Although
technically the callback is really a generated function that contains a single `void*` as input and `void*` as output.
These can be found in the `Stubs.cpp` file in the enclave. The developer never interacts with these directly and they
are used by the abi layer to forward and return parameters to the correct developer impl function for the callback.
Instead the developer interacts with a generated static function in the `Implementations.h`file in the enclave that
will use the abi to call into the callback. 

This is how the developer will interact with it:

```C++
// This is in vtl1, in a developer function where they wants to call their vtl0 untrusted function.
// pass in blob of data to send to vtl0. In this case we'll send data from a vector in the form of a blob.
size_t vector_size = 10;
std::vector<std::int8_t> int8_vector(vector_size, 0);
size_t blob_size = sizeof(std::int8_t) * vector_size;
std::int32_t result = VbsEnclave::VTL0_Callbacks::UntrustedExample_callback(int8_vector.data(), blob_size);

for (auto& value : int8_vector)
{
    // The abi should have updated each value based on what was returned by the vtl0 callback.
    // value should be 0, 1, 2, 3, 4 ... up to 9
}

```

`Note: 9` As you can see, for inout parameters the caller must allocate memory first before passing the pointer
to the abi generated function. The returned data will be memcpy'd into this pointer by the abi before control
is given back to the caller function.

`Note: 10` We explicitly add the suffix `_callback` to the end of the function name so as to avoid name conflicts
with the host to enclave functions in the generated class in vtl0.

In vtl0 there would have been a generated static class method declaration for the untrusted function in the `Stubs.h`
file. This would look like the following:

```C++
namespace VbsEnclave
{
    namespace VTL0_Stubs
    {
        struct MyEnclave
        {

        public:

            static std::int32_t UntrustedExample_callback(_Inout_ std::int8_t* int8_blob, _In_ size_t blob_size);
        };
    }
}
```

The developer must implement the declaration. One way would be as follows:

```C++
std::int32_t UntrustedExample_callback(_Inout_ std::int8_t* int8_blob, _In_ size_t blob_size);
{
    // At this point the abi layer would have copied the original vtl0's int8_blob and put it into
    // a vtl1 version which is what this functions int8_blob parameter is.
    // The abi layer catches exceptions, but the developer can catch them too.
    THROW_IF_NULL_ALLOC(int8_blob);
    size_t expected_size = 10;
    size_t array_size = blob_size / sizeof(std::int8_t);
    THROW_HR_IF(E_INVALIDARG, expected_size != array_size); // Not needed but just being explicit about our intent.
    std::vector<std::int8_t> int8_vector(array_size);
    std::iota(int8_vector.begin(), int8_vector.end(), 0);
    memcpy_s(int8_blob, blob_size, int8_vector.data(), blob_size);

    return 12345;
}
```

`Note: 11` As you can see, again the developer no longer has to worry about copying parameters into
and out of the enclave or using the `CallEnclave` Win32 api directly.

#### Call flow HostApp -> Enclave diagram (view in Github's preview mode)
```mermaid
sequenceDiagram
    participant DevelopersFunction
    participant Generated_EnclaveClass
    participant HostAppHelpers.cpp
    participant Vtl1_Generated_Stub
    participant EnclaveHelpers.cpp
    participant VTL1_Generated_abi_impl
    participant VTL1_Developer_impl

    DevelopersFunction->>Generated_EnclaveClass: invoke generated_class.func_name()
    Generated_EnclaveClass->>HostAppHelpers.cpp: put parameters in tuple, <br> create return struct and pass <br> both to CallVtl1ExportFromVtl0()
    HostAppHelpers.cpp->>Vtl1_Generated_Stub: put tuple and return struct into <br> EnclaveFunctionContext abi struct <br> and pass it to CallEnclave as input
    Vtl1_Generated_Stub->>EnclaveHelpers.cpp: invoke CallVtl1ExportFromVtl1() <br> with EnclaveFunctionContext as input
    EnclaveHelpers.cpp->>VTL1_Generated_abi_impl: extract return struct and <br> parameters from tuple and <br> forward them to func_name_abi_impl()
    VTL1_Generated_abi_impl->>VTL1_Developer_impl:copy vtl0 parameters into vtl1 parameters
    VTL1_Generated_abi_impl->>VTL1_Developer_impl:invoke func_name() with vtl1 parameters
    VTL1_Developer_impl->>VTL1_Generated_abi_impl: update inout/out params and <br> return a value if applicable to function
    VTL1_Generated_abi_impl->>VTL1_Generated_abi_impl: copy updated vtl1 inout/out <br> pointer paramerters to original vtl0 parameters
    VTL1_Generated_abi_impl->>VTL1_Generated_abi_impl: copy return value and non pointer <br> inout/out paramerters into return struct
    VTL1_Generated_abi_impl->>EnclaveHelpers.cpp: return 
    EnclaveHelpers.cpp->>EnclaveHelpers.cpp: copy return struct out of vtl1 into vtl0 memory
    EnclaveHelpers.cpp->>EnclaveHelpers.cpp: copy return struct into original <br> EnclaveFunctionContext return parameter buffer
    EnclaveHelpers.cpp->>Vtl1_Generated_Stub: return ABI HRESULT
    Vtl1_Generated_Stub->>HostAppHelpers.cpp: return ABI HRESULT as pvoid
    HostAppHelpers.cpp->>HostAppHelpers.cpp: put EnclaveFunctionContext return <br> parameter buffer into original return struct
    HostAppHelpers.cpp->>Generated_EnclaveClass: return
    Generated_EnclaveClass->>DevelopersFunction: copy non pointer values from <br> return struct into original <br> parameters then return value if applicable
```
### Data flow Enclave -> HostApp diagram (view in Github's preview mode)

```mermaid
sequenceDiagram
    participant DevelopersFunction
    participant VTL1_Generated_abi_impl_callback
    participant EnclaveHelpers.cpp
    participant Vtl0_Generated_Stub_callback
    participant HostAppHelpers.cpp
    participant VTL0_Generated_abi_impl
    participant VTL0_Developer_impl

    DevelopersFunction->>VTL1_Generated_abi_impl_callback: invoke func_name_callback()
    VTL1_Generated_abi_impl_callback->>EnclaveHelpers.cpp: copy parameters into vtl0 tuple <br> create vtl0 return struct and <br> pass both to CallVtl0CallbackFromVtl1()
    EnclaveHelpers.cpp->>Vtl0_Generated_Stub_callback: put tuple and return struct <br> into vtl0 EnclaveFunctionContext abi <br> struct and pass it to CallEnclave as input
    Vtl0_Generated_Stub_callback->>HostAppHelpers.cpp: invoke CallVtl0CallbackFromVtl0() with <br> EnclaveFunctionContext as input
    HostAppHelpers.cpp->>VTL0_Generated_abi_impl: extract return struct and <br> parameters from tuple and forward <br> them to func_name_abi_impl_callback()
    VTL0_Generated_abi_impl->>VTL0_Developer_impl: invoke func_name_callback() <br> with parameters
    VTL0_Developer_impl->>VTL0_Generated_abi_impl: update inout/out params and <br> return a value if applicable to <br> function
    VTL0_Generated_abi_impl->>VTL0_Generated_abi_impl: copy return value and <br> non pointer inout/out paramerters <br> into return struct
    VTL0_Generated_abi_impl->>HostAppHelpers.cpp: return 
    HostAppHelpers.cpp->>HostAppHelpers.cpp: put return struct into original <br> EnclaveFunctionContexts return <br> parameter buffer
    HostAppHelpers.cpp->>Vtl0_Generated_Stub_callback: return ABI HRESULT
    Vtl0_Generated_Stub_callback->>EnclaveHelpers.cpp: return ABI HRESULT as pvoid
    EnclaveHelpers.cpp->>EnclaveHelpers.cpp: copy EnclaveFunctionContext return parameter <br> buffer into original enclave return struct
    EnclaveHelpers.cpp->>VTL1_Generated_abi_impl_callback: return
    VTL1_Generated_abi_impl_callback->>DevelopersFunction: copy non pointer values <br> from return struct into original <br> vtl1 parameters then return value  <br> if applicable
```

`Note 12:` Since return values are created from the heap using `HeapAlloc`, the developer will need to use the
          `wil::unique_process_heap_ptr` smart pointer or use `HeapFree` themselves for any out parameter pointer returned to the function across the
          trust boundary.

### Things still missing
1. Deep copy of struct with pointers.
1. Flatbuffer support
1. More tests can be added, and stress tests too.
