## What are edl files

Edl stands for enclave definition language. It's a file format created by Intel, originally for their SGX hardware enclaves. However,
the format is open source and can be used as a way to declare functions that can be called between both the HostApp and the enclave.
At its core it is a normal text file that can be used as an `intermediary definition language (idl)`. Its contents resemble a simple
C header file. You define your own types (such as `enums` and `structs`), declare `host-to-enclave` function calls in the `Trusted` scope,
and `enclave-to-host` function calls in the `Untrusted` scope.

## What the `VbsEnclaveTooling` project uses edl files for

A `.edl` file is what our code generation tool uses to generate functions that interact with our ABI layer to marshal data between the 
hostApp and the enclave.

The tool generates stub functions and function declarations based on the content of the .edl file. The developer is
expected to implement the generated function declarations.

## Some basics

> [!NOTE]
>  Both Open Enclaves and Intels parsers were made specifically for working in a C environment, however we're using
it for higher level languages like C++. Because of this, we have updated our parser to be C++ centric, to allow for more types. 
See the supported types below for more information.

Here are the most notable aspects of the format that a developer needs to know in order to create and use an .edl file.

```edl
\\ Single line comment
\* Multi line comment *\

enclave 
{

    enum // Anonymous enum
    {
        enum_name,
    };   
    
    enum EnumName // Regular enum
    {
        // enum_value can only be a decimal, Hexidecimal or value from an anonymous enum
        enum_name = enum_value, 
    };

    struct StructName
    {
        // field_type can be any supported edl type.
        field_type field_name;
    };

    trusted 
    {
        return_type EnclaveMethod1(
            [parameter_attribute] parameter_type parameter_name
            );

        return_type EnclaveMethod2(
            [parameter_attribute] parameter_type parameter_name
            );
    };

    untrusted 
    {
        return_type hostAppMethod1(
            [parameter_attribute] parameter_type parameter_name
            );

        return_type hostAppMethod2(
            [parameter_attribute] parameter_type parameter_name
            );
    };
};
```

| Term                            | Description                                                                                       |
|---------------------------------|-------------------------------------------------------------------------------------------------- |
| `return_type`                   | Defines the return value type, which must be one of the supported types.                          |
| `EnclaveMethod`                 | Methods exposed from the secure `enclave` to the unsecure `hostApp`.<br> The `hostApp` calls stub functions, while the implementation is inside the `enclave`.|                                                                      |
| `parameter_attribute`           | Directives describing the parameter's direction (e.g., `[in]`, `[in, out]`, `[out]`).             |
| `parameter_type/parameter_name` | Defines a parameter's `type` and `name`. The `parameter_type` must be one of the supported types. |
| `hostAppMethod`                 | Methods exposed from the unsecure `hostApp` to the secure `enclave`.<br> The `enclave` calls stub functions, while the implementation is inside the `hostApp`. |

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

### .edl Built-in Data Types (Supported in Structs and Functions)

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
> - `vectors`, `arrays` and `structs` only support the types outlined above. `Vectors` and `arrays`
can be used as internal struct fields or function parameters.
 - `Arrays` can contain a non numeric value within the edl file. The only value it supports other than
numeric values is a value from an anonymous enum. `Arrays` are considered fixed sized, for example for `C++`
they are generated as an `std::array` values during code generation.

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

### Currently unsupported functionality within .edl files.

While our `.edl` parser is based on `Open Enclaves` implementation of `Intels` `.edl` parser. There are a couple things we do not support:

- `private` and `public` key words for the function names of both trusted and untrusted functions.
- `COM\WinRT` is not supported inside a `vbs enclave` so therefore anything `COM\WinRT` related is not supported. E.g `Events`, `Runtime classes` etc.
- `Vbs enclaves` do not support the concept of `switchless calls` calls so therefore this keyword is unsupported.
- Calling conventions (like `cdecl`, `stdcall`, `fastcall`) are not supported.
- Ability to import `C headers` into a `.edl` file to allow for types defined outside the `.edl` file is not supported. Only types defined in the `.edl` are supported.
- The words `string`  and `wstring` are supported type keywords within an `.edl` file. Using the word `string` or `wstring` as an attribute is not supported.
- Only the following attributes are supported `[in]`, `[in, out]`, `[out]`.
- Pointers in function declarations are expected to have an `[in]`, `[in, out]` or `[out]` direction attribute. `[in]` means the parameter is expected to only be used in 
  the function as input, `[out]` means the parameter is expected to be used as output and lastly `[in, out]` means the parameter can be used for both.

> [!NOTE]
> if no attributes are added the code generator will make these parameters `[in]` parameters.

- The `const` keyword is not supported. The code generator will generate all non struct/container `[in]` parameters without the `const` qualifier and all struct/container
  `[in]` parameters with the `const` qualifier. All other attributes (`[in, out]` and `[out]`) are generated without the const qualifier, regardless of type.
- Functions are not permitted to return pointers as function return values directly. Alternatively the developer could also use an out parameter.
- Ability to import one `.edl` file into another via the `import` or `include` keywords.

