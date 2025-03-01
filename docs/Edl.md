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

Note: This section was adapted from Open Enclaves [Edger8rGettingStarted.md](https://github.com/openenclave/openenclave/blob/master/docs/GettingStartedDocs/Edger8rGettingStarted.md?plain=1).
Which provides a great intro to the .edl file format. Here are the most notable aspects of the format that a developer
needs to know.

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

*parameter_constraints* are a set of directives that describe such things as if a parameter is a pointer, if the parameter is for passing in data or returning data, along with other restraints like the length of memory buffers.

*parameter_type/parameter_name* are a set of statements defining a parameter name and the associated parameter type.

*hostAppMethod_** are methods that are exposed from the unsecure hostApp to the secure enclave. The enclave will call these methods and the hostApp will implement them.

A simple example of an enclave method and hostApp method are as follows, lets call this file `AddTwoNumbers.edl`:

```edl
enclave {
    trusted {
        int32_t EnclaveAddTwoNums(
            int32_t num1,
            int32_t num2
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
- Pointers are supported but pointers to pointers and pointers to arrays are not supported. *However*, if you have an 
  [out] parameter that is a pointer, the generated code will produce this as a double Pointer. So `[out, count=1] int64_t* my_ptr`
  will become `std::int64_t** my_ptr` in the generated functions parameter.
- Pointers must have an [in] or [out] direction attribute. [in] means the parameter is expected to only be used in 
  the function as input, while out means the function is expected to update the parameter before it exits for use 
  by the calling function.
- The const keyword is not supported.
- Functions are not permitted to return pointers as function return values directly. It is expected that pointer
  values contain a respective size value for the data the pointer points. This is so the ABI layer can copy the 
  data correctly between trust boundary layers. What this means for functions is that if a pointer value 
  is expected to be returned the developer must return a struct that contains the pointer and a
  field for the size of the data the pointer points to. Alternatively the pointer could be returned via an out 
  parameter for the function which also requires being annotated with the size/count attributes. 
- For function parameters, all pointers to data types outside of structs must be annotated with a [size] or 
  [count] attribute. The only case where it is not strictly necessary is for structs. If a pointer to a struct 
  parameter is not annotated with either a [size] or [count] attribute then the `sizeof(your__struct)` will be
  used when the ABI layer copies the pointer data between the trust boundaries.

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
- enum
- struct
- HRESULT
- Arrays in the form of type[value] e.g uint8_t[10]

Note: Arrays can contain a non numeric value within the edl file. The only value it supports other than
explicitly numbers is a value from an anonymous enum. Arrays are generated as an `std::array` during
code generation.

```C++
enum
{
    my_number = 50
};

struct
{
    uint32_t[my_number] my_array;
}
```
### What are the count and size attributes used for
Both attributes are used to provide the code generator with the value it should use when copying the
parameter or field between trust boundaries:

[count] : This is used to tell the code generator that the parameter or field should be copied using
          `sizeof(parameter_type) * count` in bytes. This is useful if you have a function or struct that contains
          a variable length array of a certain type.
```
 trusted {
        // If int8_array_size contained the value of 10 then we will copy sizeof(int8_t) multiplied by 10 when 
        // copying the int8_array into and out vtl1. This behavior is the same regardless of whether the function
        // is 'trusted' or 'untrusted'.
        void ExampleFunction(
            [in, count=int8_array_size] int8_t* int8_array,
            size_t int8_array_size
        );
    };
```

[size] : This is used to tell the code generator that the parameter or field should be copied using
          `size` in bytes. This is useful if you had a function or struct that contains
          a blob of data that isn't an array and you just want to copy the raw bytes between the trust
          boundary.
```
 trusted {
        // If blob_size contained the value of 10 then we will copy exactly 10 bytes when copying the 
        // int8_blob into and out vtl1. This behavior is the same regardless of whether the function
        // is 'trusted' or 'untrusted'.
        void ExampleFunction(
            [in, count=blob_size] int8_t* int8_blob,
            size_t blob_size
        );
    };
```
