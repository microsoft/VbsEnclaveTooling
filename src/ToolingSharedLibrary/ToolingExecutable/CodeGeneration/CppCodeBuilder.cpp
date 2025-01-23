// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once 
#include <pch.h>
#include <Edl\Structures.h>
#include <Edl\Utils.h>
#include <CodeGeneration\Contants.h>
#include <CodeGeneration\CodeGeneration.h>
#include <deque>

using namespace EdlProcessor;

namespace CodeGeneration
{
    std::string CppCodeBuilder::BuildBaseHeaderFile()
    {
        return std::format("{}{}{}",
            c_autogen_header_string,
            c_default_header_includes,
            c_enclave_defines);
    }

    std::string CppCodeBuilder::EncapsulateCodeInNamespace(
        std::string_view namespace_name,
        std::string_view code)
    {
        return std::format("{} {}\n{}\n{}{}{}",
            c_cpp_namespace_keyword,
            namespace_name,
            LEFT_CURLY_BRACKET,
            code,
            RIGHT_CURLY_BRACKET,
            SEMI_COLON);
    }

    std::string CppCodeBuilder::BuildDeveloperTypesHeaderFile(std::string_view header_content)
    {
        return std::format(
            "{}{}{}\n",
            c_autogen_header_string,
            c_base_header_include,
            EncapsulateCodeInNamespace(c_default_namespace_name, header_content));
    }


    std::string CppCodeBuilder::AddUsingNamespace(std::string_view namespace_name)
    {
        return std::format("{}{}{}", c_using_namespace, namespace_name, SEMI_COLON);
    }

    std::tuple<std::string, std::string, std::string> CppCodeBuilder::BuildStartOfDefinition(
        std::string_view type_name,
        std::string_view identifier_name)
    {
        std::string header = std::format("{} {}\n", type_name, identifier_name);

        if (identifier_name.empty())
        {
            header = std::format("{}\n", type_name);
        }

        std::string start_of_body = std::format("{}\n", LEFT_CURLY_BRACKET);
        std::string end_of_body = std::format("{}{}\n", RIGHT_CURLY_BRACKET, SEMI_COLON);

        return std::make_tuple(std::move(header), std::move(start_of_body), std::move(end_of_body));
    }

    std::string CppCodeBuilder::BuildEnumDefinition(const DeveloperType& developer_types)
    {
        if (developer_types.m_items.empty())
        {
            return {};
        }

        auto is_named_enum = (developer_types.m_type_kind == EdlTypeKind::Enum);
        std::string enum_name = (is_named_enum) ? developer_types.m_name : "";

        auto [enum_header, enum_body, enum_footer] = BuildStartOfDefinition(EDL_ENUM_KEYWORD, enum_name);

        for (auto& [enum_value_name, enum_value] : developer_types.m_items)
        {
            if (enum_value.m_value)
            {
                // Value was the enum name for a value within the anonymous enum.
                Token value_token = enum_value.m_value.value();
                enum_body += std::format("{}{} = {},\n", c_four_spaces, enum_value_name, value_token.ToString());
            }
            else if (enum_value.m_is_hex)
            {
                auto hex_value = uint64_to_hex(enum_value.m_declared_position);
                enum_body += std::format("{}{} = {},\n", c_four_spaces, enum_value_name, hex_value);
            }
            else
            {
                auto decimal_value = uint64_to_decimal(enum_value.m_declared_position);
                enum_body += std::format("{}{} = {},\n", c_four_spaces, enum_value_name, decimal_value);
            }
        }

        return std::format("\n{}{}{}", enum_header, enum_body, enum_footer);
    }

    std::string CppCodeBuilder::GetTypeInfo(const EdlTypeInfo& info)
    {
        switch (info.m_type_kind)
        {
            case EdlTypeKind::UInt8:
            case EdlTypeKind::UInt16:
            case EdlTypeKind::UInt32:
            case EdlTypeKind::UInt64:
            case EdlTypeKind::Int8:
            case EdlTypeKind::Int16:
            case EdlTypeKind::Int32:
            case EdlTypeKind::Int64:
            case EdlTypeKind::String:
                return std::format("std::{}", info.m_name);
            default:
                return info.m_name;
        }
    }

    std::string CppCodeBuilder::BuildStdArrayType(
        std::string_view type, 
        const ArrayDimensions& dimensions,
        std::uint32_t index)
    {
        if (index >= dimensions.size())
        {
            return type.data();
        }

        std::string array_string = BuildStdArrayType(type, dimensions, index + 1);
        return std::format("{}{}, {}>", c_array_initializer, array_string, dimensions[index]);
    }

    std::string CppCodeBuilder::BuildNonArrayType(const Declaration& declaration)
    {
        EdlTypeInfo& info = *(declaration.m_edl_type_info);
        std::string pointer = info.m_extended_type_info ? info.m_extended_type_info->m_name : "";
        return std::format("{}{} {}", GetTypeInfo(info), pointer, declaration.m_name);
    }

    std::string CppCodeBuilder::BuildStructField(const Declaration& declaration)
    {
        if (!declaration.m_array_dimensions.empty())
        {
            EdlTypeInfo& info = *(declaration.m_edl_type_info);
            auto type_info = GetTypeInfo(info);
            auto array_info = BuildStdArrayType(type_info, declaration.m_array_dimensions);
            return std::format("{} {}", array_info, declaration.m_name);
        }

        return BuildNonArrayType(declaration);
    }

    std::string CppCodeBuilder::BuildStructDefinition(const DeveloperType& developer_types)
    {
        if (developer_types.m_fields.empty())
        {
            return {};
        }

        auto [struct_header, struct_body, struct_footer] = BuildStartOfDefinition(EDL_STRUCT_KEYWORD, developer_types.m_name);

        for (auto& field : developer_types.m_fields)
        {
            struct_body += std::format(
                "{}{}{}\n",
                c_four_spaces,
                BuildStructField(field),
                SEMI_COLON);
        }

        return std::format("\n{}\n{}{}{}{}\n",
            c_pragma_pack,
            struct_header, 
            struct_body, 
            struct_footer, 
            c_pragma_pop);
    }
}
