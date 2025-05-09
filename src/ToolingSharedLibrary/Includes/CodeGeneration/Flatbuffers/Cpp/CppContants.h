// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once 
#include <pch.h>

using namespace EdlProcessor;

namespace CodeGeneration::Flatbuffers::Cpp
{
    static inline constexpr std::string_view c_convert_to_dev_type_function_definition_reference =
R"(
    static std::unique_ptr<{}> ToDevType(const FlatbuffersDevTypes::{}& flatbuffer)
    {{
        if constexpr (std::is_empty_v<decltype(flatbuffer)>)
        {{
            return nullptr;
        }}
        auto dev_type_ret = std::make_unique<{}>();
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
    static std::unique_ptr<{}> ToDevType(const std::unique_ptr<FlatbuffersDevTypes::{}>& flatbuffer)
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
    static std::unique_ptr<FlatbuffersDevTypes::{}> ToFlatBuffer(const std::unique_ptr<{}>& dev_type)
    {{
        return {}::ToFlatBuffer(*dev_type);
    }}
)";

    static inline constexpr std::string_view c_using_statements_for_developer_struct = "\nstruct {};\n";

    static inline constexpr std::string_view c_using_statements_for_developer_enum = "\nenum;\n";

    // Dev type to flatbuffer strings

    static inline constexpr std::string_view c_dev_type_to_flatbuffer_conversion_linear_array_basic =
R"(        
        {}.assign({}.begin(), {}.end());
)";

    static inline constexpr std::string_view c_dev_type_to_flatbuffer_conversion_linear_array_structs =
R"(        
        {}.resize({}.size());
        std::transform({}.begin(), {}.end(), {}.begin(), [](const auto& elem) {{ return {}::ToFlatBuffer(elem); }});
)";

    static inline constexpr std::string_view c_dev_type_to_flatbuffer_conversion_linear_array_enums =
R"(        
        {}.resize({}.size());
        std::transform({}.begin(), {}.end(), {}.begin(), ConvertEnum<DeveloperTypes::{}, FlatbuffersDevTypes::{}>);       
)";

    static inline constexpr std::string_view c_dev_type_to_flatbuffer_conversion_linear_array_wstrings =
R"(        
        {}.resize({}.size());
        std::transform({}.begin(), {}.end(), {}.begin(), CreateWStringT);)";

    static inline constexpr std::string_view c_dev_type_to_flatbuffer_conversion_linear_vector_basic =
R"(        
        {}.assign({}.begin(), {}.end());
)";

    static inline constexpr std::string_view c_dev_type_to_flatbuffer_conversion_linear_vector_enums =
R"(        
        {}.resize({}.size());
        std::transform({}.begin(), {}.end(), {}.begin(), ConvertEnum<DeveloperTypes::{}, FlatbuffersDevTypes::{}>);       
)";

    static inline constexpr std::string_view c_dev_type_to_flatbuffer_conversion_linear_vector_structs =
R"(        
        {}.resize({}.size());
        std::transform({}.begin(), {}.end(), {}.begin(), [](const auto& elem) {{ return {}::ToFlatBuffer(elem); }});
)";

    static inline constexpr std::string_view c_dev_type_to_flatbuffer_conversion_linear_vector_wstrings =
R"(       
        {}.resize({}.size());
        std::transform({}.begin(), {}.end(), {}.begin(), CreateWStringT);)";

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
R"({} = {}::ToFlatBuffer(*{});)";

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

    static inline constexpr std::string_view c_flatbuffer_to_dev_type_conversion_linear_array_basic =
R"(         
        if (!{}.empty() && {}.size() <= {})
        {{
            std::copy({}.begin(), {}.end(), {}.begin());
        }}
)";

    static inline constexpr std::string_view c_flatbuffer_to_dev_type_conversion_linear_array_structs =
R"(         
        if (!{}.empty() && {}.size() <= {})
        {{
            for(size_t i = 0; i < {}.size() ; i++)
            {{
                if ({}[i] == nullptr) continue;
                {}[i] = {}::{}({}[i]);
            }}
        }}
)";

    static inline constexpr std::string_view c_flatbuffer_to_dev_type_conversion_linear_array_enums =
R"(         
        if (!{}.empty() && {}.size() <= {})
        {{
            std::transform({}.begin(), {}.end(), {}.begin(), ConvertEnum<FlatbuffersDevTypes::{}, DeveloperTypes::{}>);       
        }}
)";

    static inline constexpr std::string_view c_flatbuffer_to_dev_type_conversion_linear_array_wstring =
R"(         
        if (!{}.empty() && {}.size() <= {})
        {{
            for(size_t i = 0; i < {}.size() ; i++)
            {{
                if ({}[i] == nullptr) continue;
                {}[i] = ConvertToStdWString({}[i]);
            }}
        }}
)";

    static inline constexpr std::string_view c_flatbuffer_to_dev_type_conversion_linear_vector_basic =
R"(        
        {}.assign({}.begin(), {}.end());
)";

    static inline constexpr std::string_view c_flatbuffer_to_dev_type_conversion_linear_vector_enums =
R"(        
        {}.resize({}.size());
        std::transform({}.begin(), {}.end(), {}.begin(), ConvertEnum<FlatbuffersDevTypes::{}, DeveloperTypes::{}>);       
)";

    static inline constexpr std::string_view c_flatbuffer_to_dev_type_conversion_linear_vector_structs =
R"(        
        {}.reserve({}.size());
        for(size_t i = 0; i < {}.size() ; i ++)
        {{
            if ({}[i] == nullptr) continue;
            {}.emplace_back({}::{}({}[i]));
        }}
)";

    static inline constexpr std::string_view c_flatbuffer_to_dev_type_conversion_linear_vector_wstring =
R"(         
        {}.resize({}.size());
        for(size_t i = 0; i < {}.size() ; i++)
        {{
            if ({}[i] == nullptr) continue;
            {}[i] = ConvertToStdWString({}[i]);
        }}
)";

    static inline constexpr std::string_view c_flatbuffer_to_dev_type_conversion_param_ptr_base_str =
R"(       
        if ({})
        {{
            {} = std::make_unique<{}>(); 
            THROW_IF_NULL_ALLOC({}.get());
            {}
        }}              
)";

    static inline constexpr std::string_view c_flatbuffer_to_dev_type_conversion_ptr_for_primitive =
R"(    
        if ({})
        {{
            {} = std::make_unique<{}>(); 
            THROW_IF_NULL_ALLOC({}.get());
            *{} = {}.value();
        }} 
)";

    static inline constexpr std::string_view c_flatbuffer_to_dev_type_conversion_ptr_for_enum =
R"(     
        if ({})
        {{
            {} = std::make_unique<{}>(); 
            THROW_IF_NULL_ALLOC({}.get());
            *{} = static_cast<DeveloperTypes::{}>({}.value());
        }}
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
