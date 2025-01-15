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
- The word "string" is a supported type keyword within an .edl file. Using the word "string" as an attribute is not supported.
- Only the following attributes are supported [in], [out], [size], [count] are supported.
- Pointers are supported but pointers to pointers and pointers to arrays are not supported.
- Pointers must have an [in] or [out] direction attribute.
- The const keyword is not supported.

### .edl built in Data types supported
- string
- char
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
