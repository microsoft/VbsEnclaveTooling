## What are edl files

Edl stands for enclave definition language. It's a file format created by Intel, originally for their SGX hardware enclaves. However
the format is open source and can be used as a way to declare functions that can be called between both the HostApp and the enclave.
At its core it is a normal text file that can be used as an intermediary definition language, and its contents look similar to a C
header file.

## What the `VbsEnclaveTooling` project uses edl files for

.edl files are used as the artifact developers provide to the tool, so that it may generate code that will marshal data into and
out of the enclave. The generated code generates stub functions based on the functions provided within the .edl and these stub
functions use the [CallEnclave](https://learn.microsoft.com/en-us/windows/win32/api/enclaveapi/nf-enclaveapi-callenclave) api to
pass data between the hostApp and the enclave. The marshaling is handled within these stub functions.

## Some basics

Note: Both open enclave and intels parsers were made specifically for working in a C environment, however we're using it for higher level languages
like C++. Because of this, we have updated our parser to allow for a more C++ centric edl. See the supported types below.

Note: This section was adapted from Open Enclaves [Edger8rGettingStarted.md](https://github.com/openenclave/openenclave/blob/master/docs/GettingStartedDocs/Edger8rGettingStarted.md?plain=1).
Which provides a great intro to the .edl file format. Here are the most notable aspects of the format that a developer
needs to know for our uses of the format.

```edl
enclave {
    trusted {
        public return_type EnclaveMethod1(
            [parameter_constraints] parameter_type parameter_name
            );
        public return_type EnclaveMethod2(
            [parameter_constraints] parameter_type parameter_name
            );
    };

    untrusted {
        return_type hostAppMethod1(
            [parameter_constraints] parameter_type parameter_name
            );
        return_type hostAppMethod2(
            [parameter_constraints] parameter_type parameter_name
            );
    };
};
```

*return_type* is a data type defining the type of the return value.

*EnclaveMethod_** are the methods that are exposed from the secure enclave to the unsecure hostApp. The unsecure hostApp will call these methods and the enclave will implement them.

*parameter_constraints* are a set of directives that describe such things as if a parameter is a pointer.

*parameter_type/parameter_name* are a set of statements defining a parameter name and the associated parameter type.

*hostAppMethod_** are methods that are exposed from the unsecure hostApp to the secure enclave. The enclave will call these methods and the hostApp will implement them.

A simple example of an enclave method and hostApp method are as follows, lets call this file `Example.edl`:


```edl
enclave {
    struct ExampleStruct
    {
        int32_t int_field;
        vector<wstring> wstrings;
    };

    trusted {
        int32_t EnclaveAddTwoNums(
            int32_t num1,
            int32_t num2
        );

        HRESULT SecondaryExample (
            [in, out] ExampleStruct,
            vector<int8_t> bytes
        );
    };

    untrusted {
        int32_t HostAddTwoNums(
            int32_t num1,
            int32_t num2
        );
    };
};
```


## What the `VbsEnclaveTooling` project supports within .edl files.

While our .edl parser is based on Open Enclaves implementation of intels .edl parser. There are a couple things we do not support

- `private` and `public` key words for function names of both trusted and untrusted functions.
- Vbs enclaves do not support the concept of "switchless calls" calls so therefore this keyword is unsupported.
- Calling conventions (like cdecl, stdcall, fastcall) are not supported.
- Ability to import C headers into a .edl file to allow for types defined outside the .edl file is not supported. Only types defined in the .edl are supported.
- The words `string`  and `wstring` are supported type keywords within an .edl file. Using the word `string` or `wstring` as an attribute is not supported.
- Only the following attributes are supported [in], [out], [size], [count] are supported.
- Pointers in function declarations are expected to have [in], [in, out] or [out] direction attribute. [in] means the parameter is expected to only be used in 
  the function as input, while out means the function is expected to update the parameter before it exits for use 
  by the calling function. Note: if no attributes are added the code generator will make these parameters [in] parameters.
- The const keyword is not supported. The codegen layer will generate all non struct `[in]` parameters as `const <type>` and all struct `[in]` parameters
  `const <type>&`. All other attributes (`inout` and `out`) are generated without the const modifier. If the `[out]` attribute is used with a non pointer type
  then it will be generated as `<type>&`.
- Functions are not permitted to return pointers as function return values directly. Alternatively the developer could also use an out parameter.


### .edl built in Data types supported in both structs and functions
- string
- wstring
- char
- wchar_t
- float
- double
- size_t
- int8_t
- int16_t
- int32_t
- int64_t
- uint8_t
- uint16_t
- uint32_t
- uint64_t
- uintptr_t
- enum
- struct
- pointers in the form of `*`
- HRESULT
- Arrays in the form of `type[value]` e.g `uint8_t[10]`
- Vectors in the form of vector<type> e.g vector<string>

Note: Vectors only support the types outlined above. For structs, only structs that appear in the .edl
file can be used as a type within a vector declaration. Vectors can be used as internal struct fields
or function parameters.

Note: Arrays can contain a non numeric value within the edl file. The only value it supports other than
numeric values is a value from an anonymous enum. Arrays are considered fixed sized and are generated as
an `std::array` during code generation.

```C++
enum
{
    my_number = 50
};

struct
{
    uint32_t[my_number] my_array; // This also works in a function declaration.
}
```
