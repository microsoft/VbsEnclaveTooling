## What are .edl files

EDL (enclave definition language) is an open file format created by Intel, originally for their SGX hardware enclaves.
It's a text format (loosely resembling C), with a simple grammar, that can be used as an `intermediary definition language (idl)` to declare functions that can be called
between both the hostApp and the enclave. You define your own types (such as `enums` and `structs`), declare `host-to-enclave` function calls in the `trusted` scope,
and `enclave-to-host` function calls in the `untrusted` scope.

## What the `VbsEnclaveTooling` project uses .edl files for

An `.edl` file is what our code generation tool uses to generate functions that interact with our ABI layer to marshal data between the 
hostApp and the enclave.

The tool generates stub functions and function declarations based on the content of the .edl file. The developer is
expected to implement the generated function declarations.

## Some basics

> [!NOTE]
>  Both Open Enclave's and Intel's parsers were made specifically for working in a C environment, however we're using
it for higher level languages like C++. Because of this, we have updated our parser to be C++ centric, to allow for more types. 
See the supported types below for more information.

Here is the general structure and grammar of our .edl format.

> [!NOTE]
>  We do not currently support the `import` statement.

```edl
\\ Single line comment
\* Multi line comment *\

enclave 
{

    enum // Anonymous enum
    {
        <enum_name>,
    };   
    
    enum <Enum> // Regular enum
    {
        // enum_value can only be a decimal, Hexidecimal or value from an anonymous enum
        <enum_field> = <enum_value>, 
    };

    struct <Struct>
    {
        // field_type can be any supported edl type.
        <field_type> <field_name>;
    };

    trusted 
    {
        <return_type> <EnclaveMethod>(
            [attr] <parameter_type> <parameter_name>
            );
    };

    untrusted 
    {
        <return_type> <HostappMethod>(
            [attr] <parameter_type> <parameter_name>
            );
    };
};
```

| Term                            | Description                                                                                       |
|---------------------------------|-------------------------------------------------------------------------------------------------- |
| `return_type`                   | Defines the return value type, which must be one of the supported types.                          |
| `parameter_type`                | Defines a parameter's `type`. Must be one of the supported types. |
| `parameter_name`                | Defines a parameter's `name`. |
| `attr`                          | Directives describing the parameter's direction (e.g., `[in]`, `[in, out]`, `[out]`).             |
| `EnclaveMethod`                 | Methods exposed from the secure `enclave` to the unsecure `hostApp`.<br> The `hostApp` calls stub functions, while the implementation is inside the `enclave`.|                                                                      |
| `HostappMethod`                 | Methods exposed from the unsecure `hostApp` to the secure `enclave`.<br> The `enclave` calls stub functions, while the implementation is inside the `hostApp`. |

A simple example of a `.edl` file.

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
            vector<int8_t> bytes // a data blob
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

### Built-in Data Types

| Category          | Types                                                                 |
|-------------------|------------------------------------------------------------------------|
| Basic Types       | `char`, `wchar_t`, `float`, `double`, `size_t`, `HRESULT`              |
| Integer Types     | `int8_t`, `int16_t`, `int32_t`, `int64_t`<br>`uint8_t`, `uint16_t`,`uint32_t`, `uint64_t`, `uintptr_t` |
| String Types      | `string`, `wstring`                                                    |
| Complex Types     | `enum`, `struct`                                                       |
| Pointer Types     | Pointers in the form of `*` (e.g, `uint32_t *`)                        |
| Array Types       | Arrays in the form of `type name[value]` (e.g., `uint8_t numbers[10]`) |
| Vector Types      | Vectors in the form of `vector<type>` (e.g., `vector<string>`)         |

> [!NOTE]
> - `vectors`, `arrays` and `structs` only support the types outlined above. `vectors` and `arrays`
can be used as internal struct fields or function parameters.
 - `arrays` can contain a non-numeric value within the edl file. The only value it supports other than
numeric values is a value from an anonymous enum. `arrays` are considered fixed-sized, and in `C++`
are generated as a `std::array` during code generation.

Example showing how using an `anonymous enum` value can be used with an `array` in a `.edl` file. 
```C++
enum
{
    my_number = 50
};

struct
{
    uint32_t[my_number] my_array; // This also works in a function declaration.
};
```

### Unsupported functionality

While our `.edl` parser is based on Open Enclave's implementation of Intel's .edl parser, there are some things we do not support:

- `private` and `public` keywords for the function names of both trusted and untrusted functions.
- `COM\WinRT` is not supported inside a `vbs enclave`. e.g `Events`, `RuntimeClasses` etc.
- The concept of switchless calls is not encouraged, so the `switchless` keyword is unsupported.
- Calling conventions (like `cdecl`, `stdcall`, `fastcall`) are not supported.
- Ability to import `C headers` into an `.edl` file to allow for types defined outside the `.edl` file is not supported. Only types defined in the `.edl` are supported.
- The words `string`  and `wstring` are supported type keywords within an `.edl` file. Using the word `string` or `wstring` as an attribute is not supported.
- Only the following attributes are supported `[in]`, `[in, out]`, `[out]`.
- Pointers in function declarations are expected to have an `[in]`, `[in, out]` or `[out]` direction attribute. `[in]` means the parameter is expected to only be used in 
  the function as input, `[out]` means the parameter is expected to be used as output and lastly `[in, out]` means the parameter can be used for both.

> [!NOTE]
> If no attributes are specified, parameters default to `[in]`.

- The `const` keyword is not supported. In code generation, all non-struct/non-container `[in]` parameters won't have the `const` qualifier; all struct/container
  `[in]` parameters will have the `const` qualifier. All other attributes (`[in, out]` and `[out]`) are generated without the const qualifier, regardless of type.
- Functions are not permitted to return raw pointers; use `[out]` with `*` to return a smart pointer.
- The ability to compose `.edl` files with the `import` or `include` keywords is not supported.

