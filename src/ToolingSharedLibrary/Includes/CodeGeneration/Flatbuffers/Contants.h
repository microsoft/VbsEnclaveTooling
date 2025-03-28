// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once 
#include <pch.h>
#include <Edl\Structures.h>

using namespace EdlProcessor;

namespace CodeGeneration::Flatbuffers
{
    static inline constexpr std::string_view c_flatbuffer_compiler_name = "flatc.exe";

    static inline constexpr std::string_view c_flatbuffer_compiler_default_path = "{}\\flatc.exe";

    static inline constexpr std::string_view c_cpp_gen_args = "--cpp --no-prefix --cpp-std c++17 --gen-object-api --force-empty";

    // Since we allow Hex inside the edl enum, we will default to uint64 to cover all scenarios.
    static inline constexpr std::string_view c_enum_definition = "\nenum {} : uint64 {{\n{}}}\n";

    static inline constexpr std::string_view c_table_definition = "\ntable {} {{\n{} }}\n";

    static inline constexpr std::string_view c_flatbuffer_namespace = "\nnamespace FlatbuffersDevTypes;\n";

    static inline constexpr std::string_view c_flatbuffer_wstring_table =
    R"(
    table WString {
      wchars:[int16];
    }
    )";

    static inline constexpr std::string_view c_flatbuffer_register_callback_tables =
    R"(
    table AbiRegisterVtl0Callbacks_args {
      callbacks:[uint64];
      m__return_value_:int32;
    }
    )";

    static inline constexpr std::string_view c_flatbuffer_function_context =
    R"(
    table {} {{
      {}
    }}
    )";

    static inline constexpr std::string_view c_flatbuffers_helper_functions =
R"(
inline std::wstring ConvertToStdWString(const FlatbuffersDevTypes::WStringT& wstr)
{
    return std::wstring(wstr.wchars.begin(), wstr.wchars.end());
}
inline std::wstring ConvertToStdWString(const std::unique_ptr<FlatbuffersDevTypes::WStringT>& wstr)
{
    return ConvertToStdWString(*wstr);
}
inline std::unique_ptr<FlatbuffersDevTypes::WStringT> CreateWStringT(const std::wstring& wchars)
{
    auto wchart_ptr = std::make_unique<FlatbuffersDevTypes::WStringT>();
    THROW_IF_NULL_ALLOC(wchart_ptr);
    wchart_ptr->wchars.assign(wchars.begin(), wchars.end());
    return wchart_ptr;
}
template<typename T, typename U>
inline U ConvertEnum(T enum_1)
{
    return static_cast<U>(enum_1);
}
    )";

    static inline constexpr std::string_view c_flatbuffer_fbs_filename = "vbsenclave_flatbuffer_support.fbs";

    static inline std::string c_failed_to_compile_flatbuffer_msg = std::format("Compiling flatbuffer schema file: {}", c_flatbuffer_fbs_filename);

    static inline std::string c_succeeded_compiling_flatbuffer_msg = std::format("Flatbuffer schema {} compiled successfuly", c_flatbuffer_fbs_filename);

    static inline constexpr std::string_view c_dev_type_name = "dev_type";

    static inline constexpr std::string_view c_flatbuffer_type_name = "flatbuffer";

    static inline constexpr std::string_view c_flatbuffer_root_type = "\nroot_type __root_table;\n";

    static inline constexpr std::string_view c_statements_for_developer_struct = "\nstruct {};\n";

    static inline constexpr std::string_view c_statements_for_developer_enum = "\nenum;\n";

    static inline constexpr std::string_view c_function_args_struct = "{}_args";

    static inline constexpr std::string_view c_flatbuffer_root_table = R"(
    table __root_table
    {
    }
    )";

    static inline constexpr std::string_view c_function_args_constructor =
    R"(    {}() = default;
        {}({}) :
    {}    {{}}
    )";

    static inline constexpr std::string_view c_function_args_initializer_list =
    R"(        {} {}({})
    )";

    static inline constexpr std::string_view c_flatbuffer_native_table_type_suffix = "{}T";

    static inline constexpr std::string_view c_to_flatbuffer_table_type_receiver_suffix = "{}_argsT";

    static inline constexpr std::string_view c_convert_to_dev_type_function_definition_reference =
    R"(
    static std::shared_ptr<{}> ToDevType(const FlatbuffersDevTypes::{}& flatbuffer)
    {{
        if constexpr (std::is_empty_v<decltype(flatbuffer)>)
        {{
            return nullptr;
        }}
        auto dev_type_ret = std::make_shared<{}>();
        THROW_IF_NULL_ALLOC(dev_type_ret);
        auto& dev_type = *dev_type_ret;
{}
        return dev_type_ret;
    }}
    )";

    static inline constexpr std::string_view c_convert_to_dev_type_function_definition_no_ptr =
    R"(
    static {} ToDevTypeNoPtr(const FlatbuffersDevTypes::{}& flatbuffer)
    {{
        {} dev_type = {{}};
{}
        return dev_type;
    }}
    )";

    static inline constexpr std::string_view c_convert_to_dev_type_function_definition_no_ptr2 =
    R"(
    static {} ToDevTypeNoPtr(const std::unique_ptr<FlatbuffersDevTypes::{}>& flatbuffer)
    {{
        return {}::ToDevTypeNoPtr(*flatbuffer);
    }}
    )";

    static inline constexpr std::string_view c_convert_to_dev_type_function_definition_shared_ptr =
    R"(
    static std::shared_ptr<{}> ToDevType(const std::unique_ptr<FlatbuffersDevTypes::{}>& flatbuffer)
    {{
        return {}::ToDevType(*flatbuffer);
    }}
    )";

    static inline constexpr std::string_view c_convert_to_flatbuffer_function_definition_reference =
    R"(
    static std::unique_ptr<FlatbuffersDevTypes::{}> ToFlatBuffer(const {}& dev_type)
    {{
        if constexpr (std::is_empty_v<decltype(dev_type)>)
        {{
            return nullptr;
        }}
        auto flatbuffer_ret = std::make_unique<FlatbuffersDevTypes::{}>();
        THROW_IF_NULL_ALLOC(flatbuffer_ret);
        auto& flatbuffer = *flatbuffer_ret;
{}
        return flatbuffer_ret;
    }}
    )";

    static inline constexpr std::string_view c_convert_to_flatbuffer_function_definition_multi_params =
    R"(
    static std::unique_ptr<FlatbuffersDevTypes::{}> ToFlatBuffer({})
    {{
        if constexpr (std::is_empty_v<FlatbuffersDevTypes::{}>)
        {{
            return nullptr;
        }}
        auto flatbuffer_ret = std::make_unique<FlatbuffersDevTypes::{}>();
        THROW_IF_NULL_ALLOC(flatbuffer_ret);
        auto& flatbuffer = *flatbuffer_ret;
{}
        return flatbuffer_ret;
    }}
    )";

    static inline constexpr std::string_view c_convert_to_flatbuffer_function_definition_unique_ptr =
    R"(
    static std::unique_ptr<FlatbuffersDevTypes::{}> ToFlatBuffer(const std::shared_ptr<{}>& dev_type)
    {{
        return {}::ToFlatBuffer(*dev_type);
    }}
    )";

    static inline constexpr std::string_view c_using_statements_for_developer_struct = "\nstruct {};\n";

    static inline constexpr std::string_view c_using_statements_for_developer_enum = "\nenum;\n";

    // Dev type to flatbuffer strings

    static inline constexpr std::string_view c_dev_type_to_flatbuffer_conversion_ptr_base_smartptr =
R"(
        if ({})
        {{
            {}
        }}
)";

    static inline constexpr std::string_view c_dev_type_to_flatbuffer_conversion_ptr_for_primitive =
R"({} = *{};)";

    static inline constexpr std::string_view c_dev_type_to_flatbuffer_conversion_ptr_for_enum =
R"({} = static_cast<FlatbuffersDevTypes::{}>(*{});)";

    static inline constexpr std::string_view c_dev_type_to_flatbuffer_conversion_ptr_for_struct =
R"({} = {}::ToFlatBuffer({});)";

    static inline constexpr std::string_view c_dev_type_to_flatbuffer_conversion_basic =
R"(        
        {} = {};
)";
    static inline constexpr std::string_view c_dev_type_to_flatbuffer_conversion_wstring =
R"(        
        {} = CreateWStringT({});
)";

    static inline constexpr std::string_view c_dev_type_to_flatbuffer_conversion_enum =
R"(        
        {} = static_cast<FlatbuffersDevTypes::{}>({});
)";

    static inline constexpr std::string_view c_dev_type_to_flatbuffer_conversion_nestedstruct =
R"(        
        {} = {}::ToFlatBuffer({});
)";

    // flatbuffer to dev type strings

    static inline constexpr std::string_view c_flatbuffer_to_dev_type_conversion_param_ptr_base_str =
R"(       
        if ({})
        {{
            {} = std::make_shared<{}>(); 
            THROW_IF_NULL_ALLOC({}.get());
            {}
        }}              
)";

    static inline constexpr std::string_view c_flatbuffer_to_dev_type_conversion_ptr_for_primitive =
        R"(      
        {} = std::make_shared<{}>(); 
        THROW_IF_NULL_ALLOC({}.get());
        *{} = {};
)";

    static inline constexpr std::string_view c_flatbuffer_to_dev_type_conversion_ptr_for_enum =
        R"(     
        {} = std::make_shared<{}>(); 
        THROW_IF_NULL_ALLOC({}.get());
        *{} = static_cast<DeveloperTypes::{}>({});
)";

    static inline constexpr std::string_view c_flatbuffer_to_dev_type_conversion_ptr_for_struct =
R"(      
        if ({})
        {{
            {} = {}::{}(*{});
        }} 
)";

    static inline constexpr std::string_view c_flatbuffer_to_dev_type_conversion_basic =
R"(     
        {} = {};
)";

    static inline constexpr std::string_view c_flatbuffer_to_dev_type_conversion_wstring =
R"(        
        if ({})
        {{ 
            {} = ConvertToStdWString({});
        }}
)";

    static inline constexpr std::string_view c_flatbuffer_to_dev_type_conversion_enum =
R"(        
        {} = static_cast<DeveloperTypes::{}>({});
)";

    static inline constexpr std::string_view c_flatbuffer_to_dev_type_conversion_nestedstruct =
R"(        
        if ({})
        {{ 
            {} = {}::{}(*{});
        }}
)";

    static inline constexpr std::string_view c_params_struct = "dev_type_params";
}
