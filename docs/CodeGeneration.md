# Code Generation

Our code generation allows developers to call functions that live in either VTL1 or
VTL0 in a natural way without having to interact with the `CallEnclave` API directly, nor deal with the unstructured `void *`
contract when passing data into/out-of an enclave. The generated code will package up your function arguments, copy them safely
across the VTL boundary, then forward them to your ultimate function implementation. This allows developers to focus only 
on their business logic, instead of the logic around the trust boundary. 

## How it works
1. Create an .edl file like [example edl](../SampleApps/SampleApps/SampleEnclaveInterface.edl).
   See: [Edl format](./Edl.md) for more current support.
1. Add the `Microsoft.Windows.VbsEnclave.CodeGenerator` nuget package to both your `enclave` and `hostApp` projects. 
1. Add properties to your project as listed in [README.md](../README.md).
1. Build your projects.

Generated `enclave` project artifacts:
```
    VbsEnclave/
    |
    |--- Enclave/
            |--- Abi
                  |--- AbiTypes.h
                  |--- Definitions.h
                  |--- Exports.<Edl-Filename>.cpp
                  |--- FlatbufferTypes.fbs
                  |--- FlatbufferTypes.h
                  |--- LinkerPragmas.<Edl-Filename>.cpp
                  |--- TypeMetadata.h
            |--- Implementation
                  |--- Trusted.h
                  |--- Types.h
            |--- Stubs
                  |--- Untrusted.h
   ```

Generated `hostApp` project artifacts:
   ```
    VbsEnclave/
    |
    |--- HostApp/
            |--- Abi
                  |--- AbiTypes.h
                  |--- Definitions.h
                  |--- FlatbufferTypes.fbs
                  |--- FlatbufferTypes.h
                  |--- TypeMetadata.h
            |--- Implementation
                  |--- Types.h
                  |--- Untrusted.h
            |--- Stubs
                  |--- Trusted.h
```

  > [!NOTE]
  > - The default output directory is `$(ProjectDir)\Generated Files`
  >  - If you're using the nuget package the files will automatically be added to the projects build so there is no need to explicitly include them.

## Files Generated

  > [!NOTE]
  > The developer is only expected to interact with files generated in the `Implementation` and the `Stubs` directories.

### ABI files
| File              | Description                                                 |
|-------------------|-------------------------------------------------------------|
| `Abi\Abitypes.h` | Defines data structures for packaging function parameters for use with the VBS enclave codegen ABI. |
| `Abi\Definitions.h` | Contains methods used to forward and return parameters to and from the vbs enclave codegen ABI. This is the glue code between the `hostApp` and the `enclave`.  |
| `Abi\Exports.<Edl-Filename>.cpp` | Contains the generated functions that are exported by the enclave. These functions call into a sibling functions generated in `Abi\Definitions.h`. |
| `Abi\FlatbufferTypes.h` | Defines a `Flatbuffer` type for each type defined in `Abi\AbiType.h` and `Implementation\Types.h`.  |
| `Abi\FlatbufferTypes.fbs` | Defines a `Flatbuffer` schema that generates the types found in `Abi\FlatbufferTypes.h`.  |
| `Abi\LinkerPragmas.<Edl-Filename>.cpp` | Contains a `#pragma comment(linker, /include)` for each generated function in `Abi\Exports.<Edl-Filename>.cpp`. This ensures that functions generated in a developer's static library are exported from the enclave dll.  |
| `Abi\TypeMetadata.h` | Contains data needed to perform the conversion between `Flatbuffer types` and the types found in `Abi\AbiType.h` and `Implementation\Types.h`. |

### Enclave files
| File              | Description                                                 |
|-------------------|-------------------------------------------------------------|
| `Implementation\Trusted.h` | Contains all of the function declarations that the developer outlined in the `trusted` scope of the `.edl` file. The developer must implement these. |
| `Implementation\Types.h` | Defines C++ parameter types the developer can pass into `.edl`-specified functions. This is the `parameter currency` of the interfacing layer that the developer's app logic & enclave logic uses to speak to codegen'd functions. |
| `Stubs\Untrusted.h` | Contains stubs functions that the developer will call from inside the `enclave` to invoke the implementation in the `hostApp`. |

### HostApp files
| File              | Description                                                 |
|-------------------|-------------------------------------------------------------|
| `Implementation\Untrusted.h` | Contains all of the function declarations that the developer outlined in the `untrusted` scope of the `.edl` file. The developer must implement these. |
| `Implementation\Types.h` | Defines C++ parameter types developer can pass into `.edl`-specified functions. This is the `parameter currency` of the interfacing layer that the developer's app logic & enclave logic uses to speak to codegen'd functions. |
| `Stubs\Trusted.h` | Contains a `class` that is constructed with a `void*` to an enclave instance, and includes stub functions for invoking the implementation in the `enclave` from the `hostApp`. |

## ABI layer

The `Microsoft.Windows.VbsEnclave.CodeGenerator` nuget package exports `7 non-generated .h files` that your codegen'd layer (above) relies on. You typically won't ever need to interact with these files explicitly.

```C++
#include <VbsEnclaveABI\Shared\VbsEnclaveAbiBase.h>
#include <VbsEnclaveABI\Shared\ConversionHelpers.h>
#include <VbsEnclaveABI\Enclave\EnclaveHelpers.h>
#include <VbsEnclaveABI\Enclave\Vtl0Pointers.h>
#include <VbsEnclaveABI\Enclave\MemoryAllocation.h>
#include <VbsEnclaveABI\Enclave\MemoryChecks.h>
#include <VbsEnclaveABI\Host\HostHelpers.h>
```

### Shared by both Enclave and HostApp

1. `VbsEnclaveAbiBase.h` - Defines the core structures, macros and helper functions needed to support parameter packing
                           and unpacking.
1. `ConversionHelpers.h` - defines Helper functions for translating `Flatbuffer` types to and from EDL code-generated types.

### Available only to Enclave

1. `EnclaveHelpers.h`    - Provides helper functions used by the generated functions to facilitate marshaling data into
                           and out of the `enclave`. These functions leverage the [EnclaveCopyIntoEnclave](https://learn.microsoft.com/windows/win32/api/winenclaveapi/nf-winenclaveapi-enclavecopyintoenclave) and [EnclaveCopyOutOfEnclave ](https://learn.microsoft.com/en-us/windows/win32/api/winenclaveapi/nf-winenclaveapi-enclavecopyoutofenclave) Win32 APIs.

1. `Vtl0Pointers.h`      - Contains smart pointers that are used when dealing with `hostApp` memory inside the `enclave`.
1. `MemoryAllocation.h`  - Contains functions to allocate and retrieve `hostApp` memory from inside an `enclave`.
1. `MemoryChecks.h`      - Contains checks to verify that data is either in `hostApp` memory or `enclave` memory.

### Available only to HostApp

1. `HostHelpers.h`         - Provides helper functions used by the generated functions to facilitate marshaling data into
                           and out of the `hostApp`.

## Example generated code usage

For the following example we will assume the developer used the following `.edl` file content and the `edlcodegen`
executable generated code based on it.

```C++
// example edl
enclave {
    struct ExampleStruct
    {
        vector<string> vec_str;
        wstring arr_str[5];
        int32_t* int_ptr;
    };

    trusted {
        string TrustedExample(
            [out] vector<int8_t> int8_vec,
            int64_t* some_ptr, // no attribute so by default will be _In_ attribute.
            [in, out] ExampleStruct ex_struct
        );
    };

    untrusted {
        HRESULT UntrustedExample(
            [in, out] string some_string,
            [out] wstring some_wstring
        );
    };
};
```

Imagine the developer does the following:
1. Uses the string `MyEnclave` in the `VbsEnclaveVtl0ClassName` property in their `hostApp` .vcxproj file
1. Uses the string `VbsEnclave` as the `VbsEnclaveNamespace` property in both their `hostApp` and `enclave` .vcxproj files.

The following sections describe what will be generated and how the developer will interact with the generated code.

### Trusted scope: HostApp -> Enclave

The generated class contains a stub function for every function the developer declares in the `trusted` scope of the .edl file.

The expectation is for a developer to use the generated class in the following way:

```C++
// This is in the hostApp, in a developer function where they want to call their enclave trusted function.
// We have omitted the code to create, initialize and load the enclave's void* instance, but imagine we have a void* variable we 
// called enclave_void_star after we created it.
#include <VbsEnclave\HostApp\Stubs\Trusted.h> // generated file.

auto generated_class = VbsEnclave::Trusted::Stubs::MyEnclave(enclave_void_star);
THROW_IF_FAILED(generated_class.RegisterVtl0Callbacks()); // call RegisterVtl0Callbacks at least once.
std::vector<int8_t> int8_vec {};
int64_t some_int64 = 0;
ExampleStruct ex_struct{};
ex_struct.vec_str.push_back("string 1");
ex_struct.arr_str[0] = L"wstring 1";
int32_t int32_val = 67678;
ex_struct.int_ptr = &int32_val;

std::string enclave_str = generated_class.TrustedExample(int8_vec, &some_int64, ex_struct);
for (size_t i = 0; i < int8_vec.size(); i++)
{
    // Should print 0, 1, 2, 3, 4 ... up to 9
    std::cout <<  int8_vec[i] << std::endl;
}

for (auto& value : ex_struct.vec_str)
{
    // Should print "string 1", "string 2" , "string 3" etc
    std::cout <<  value << std::endl;
}

for (auto& value : ex_struct.arr_str)
{
    // Should print "wstring 1", "wstring 2" , "wstring 3" etc
    std::wcout <<  value << std::endl;
}

std::cout <<  *ex_struct.int_ptr << std::endl; // should print 20
std::cout <<  enclave_str << std::endl; // should print "String from enclave!"
```

> [!NOTE]
> `RegisterVtl0Callbacks` is always generated, regardless of whether `trusted` or `untrusted`
functions are defined in the .edl file. It registers memory allocation callbacks needed for 
parameter passing between hostApp and enclave, and must be called at least once before using
any of the class's methods. 

Back in the `enclave` a declaration for the enclave function would have been generated in the
`Implementation\Trusted.h` file. The developer is expected to create a definition for this declaration. 

Using the example `.edl` above the following declaration would be generated.

```C++
// The generated enclave function declarations are encapsulated
// in the <Namespace provided>::Trusted::Implementation namespace.
namespace VbsEnclave
{
    namespace Trusted::Implementation
    {
        std::string TrustedExample(
            _Out_ std::vector<int8_t>& int8_vec, 
            _In_ const std::int64_t* some_ptr,
            _Inout_ ExampleStruct& ex_struct );
    }
}
```

> [!NOTE]
> In the C++ case when the `out` annotation is used in tandem with a pointer,
the code generator will generate the parameter as a reference to a `unique_ptr`.


Continuing on, the developer might implement the declaration like this:
```C++
#include <VbsEnclave\Enclave\Implementation\Trusted.h> // generated file.

using namespace VbsEnclave;

std::string Trusted::Implementation::TrustedExample(
    _Out_ std::vector<int8_t>& int8_vec, 
    _In_ const std::int64_t* some_ptr,
    _Inout_ ExampleStruct& ex_struct)
{
    int8_vec.resize(10);
    std::iota(int8_vec.begin(), int8_vec.end(), 0);
    THROW_HR_IF_NULL(E_INVALIDARG, ex_struct.int_ptr);
    *ex_struct.int_ptr = 20;
    
    for (int i = 2; i < 6; i++)
    {
        ex_struct.vec_str.push_back("string "+ std::to_string(i));
    }

    for (int i = 2; i < ex_struct.arr_str.size(); i++)
    {
        ex_struct.arr_str.push_back(L"wstring "+ std::to_wstring(i));
    }

    *ex_struct.int_ptr = 20;

    // Validate that the pointer was copied correctly. (It should!)
    THROW_HR_IF_NULL(E_INVALIDARG, some_ptr);
    THROW_HR_IF(E_INVALIDARG, *some_ptr != 67678);

    return "String from enclave!";
}
```

> [!NOTE]
> From this demonstration we can see that the developers business logic 
never directly uses the `CallEnclave` API, creates a module `.def` file,
or calls the exported enclave functions directly. This is all handled by
the `CodeGen` layer.

### Untrusted scope: HostApp <- Enclave

In the `untrusted` scenario, the function declarations are generated
in `Implementation\Untrusted.h`. These are implemented in the `hostApp` by the developer
and the developer calls them via the generated stub functions inside the `enclave`.

This is how the developer might interact with it:

```C++
// This is inside the enclave, in the developers business logic where they want
// to call the hostApp's implementation they defined.
#include <VbsEnclave\Enclave\Stubs\Untrusted.h> // generated file.

std::string str1 = "The quick brown";
std::wstring wstr1{};
HRESULT result = VbsEnclave::Untrusted::Stubs::UntrustedExample(str1, wstr1);

// Verifying expected str1 and wstr1 values post call
THROW_IF_FAILED(result);
THROW_HR_IF(INVALIDARG, str1 != "The quick brown fox jumps over the lazy dog");
THROW_HR_IF(INVALIDARG, wstr1 != L"HELLO WORLD FROM VTL0");

```
In the `hostApp` there will be a generated function declaration for this
stub function in `Implementation\Untrusted.h`. This would look like the following:

```C++
namespace VbsEnclave
{
    namespace Untrusted::Implementation
    {
        static HRESULT UntrustedExample(
            _Inout_ std::string& some_string,
            _Out_ std::wstring& some_wstring);
    };
    
}
```

The developer must implement this declaration. One way would be the following:

```C++
#include <VbsEnclave\HostApp\Implementation\Untrusted.h> // generated file.

using namespace VbsEnclave;

HRESULT Untrusted::Implementation::UntrustedExample(
        _Inout_ std::string& some_string,
        _Out_ std::wstring& some_wstring)
{
    // Verifying that the initial values for the some_string and some_wstring
    // parameters are what we expect.
    RETURN_HR_IF(INVALIDARG, some_string != "The quick brown");
    RETURN_HR_IF(INVALIDARG, some_wstring != L"");
    
    some_string += " fox jumps over the lazy dog";
    some_wstring = L"HELLO WORLD FROM VTL0";

    return S_OK;
}
```

> [!NOTE]
> The developer only needs to worry about their business logic. They do not
need to worry about copying parameters into and out of the `enclave` or 
using the `CallEnclave` Win32 API directly.
