// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once 
#include <pch.h>
#include <Edl\Structures.h>
#include <Edl\Utils.h>
#include <CodeGeneration\Rust\Constants.h>
#include <CodeGeneration\Rust\CodeGeneration.h>
#include <sstream>

using namespace EdlProcessor;
using namespace CodeGeneration::Flatbuffers;

namespace CodeGeneration::Rust
{
    std::string CodeBuilder::GenerateDeveloperTypesModuleFile(
        std::string_view developer_namespace_name,
        VirtualTrustLayerKind vtl_kind,
        const OrderedMap<std::string, DeveloperType>& developer_types_map)
    {
        std::ostringstream types_module {};
        std::ostringstream enums_definitions {};
        std::ostringstream anon_enums_constants {};
        std::ostringstream struct_declarations {};

        for (auto& type : developer_types_map.values())
        {
            if (type.IsEdlType(EdlTypeKind::Enum))
            {
                enums_definitions << BuildEnumDefinition(type);
            }
            else if (type.IsEdlType(EdlTypeKind::AnonymousEnum))
            {
                anon_enums_constants << GenerateConstantsFromAnonEnum(type);
            }
        }

        types_module << anon_enums_constants.str() << enums_definitions.str();

        for (auto& type : developer_types_map.values())
        {
            if (type.IsEdlType(EdlTypeKind::Struct))
            {
                types_module << BuildStructDefinition(type.m_name, type.m_fields);
            }
        }

        std::string vec_and_str_imports = vtl_kind == VirtualTrustLayerKind::Enclave ? c_enclave_vec_str.data() : "";
        return std::format(
            c_dev_types_file,
            c_autogen_header_string,
            vec_and_str_imports,
            developer_namespace_name,
            types_module.str());
    }

    std::string CodeBuilder::GenerateAbiTypesModuleFile(
        std::string_view developer_namespace_name,
        VirtualTrustLayerKind vtl_kind,
        std::span<const DeveloperType> abi_function_developer_types)
    {
        std::ostringstream types_module {};

        for (auto& type : abi_function_developer_types)
        {
            types_module << BuildStructDefinition(type.m_name, type.m_fields);
        }

        std::string vec_and_str_imports = vtl_kind == VirtualTrustLayerKind::Enclave ? c_enclave_vec_str.data() : "";

        return std::format(
            c_abi_function_types_file,
            c_autogen_header_string,
            vec_and_str_imports,
            developer_namespace_name,
            types_module.str());
    }

    Definition CodeBuilder::BuildStartOfDefinition(
        std::string_view type_name,
        std::string_view identifier_name,
        std::size_t num_of_tabs)
    {
        Definition definition {};
        definition.m_header << std::format("pub {} {} {}\n", type_name, identifier_name, LEFT_CURLY_BRACKET);
        definition.m_footer << std::format("{}\n", RIGHT_CURLY_BRACKET);

        return definition;
    }

    std::string CodeBuilder::BuildEnumDefinition(const DeveloperType& developer_types)
    {
        std::ostringstream full_enum {};

        auto [enum_header, _, enum_footer] = BuildStartOfDefinition(
            "enum",
            developer_types.m_name,
            c_type_definition_tab_count
        );

        // Add top level enum attributes
        full_enum << std::format(c_enum_attributes, developer_types.m_name);
        full_enum << enum_header.str();
        full_enum << std::format("{}#[default]\n", c_four_spaces);

        for (auto& enum_value : developer_types.m_items.values())
        {
            full_enum << std::format(
                "{}{} = {},\n",
                c_four_spaces,
                enum_value.m_name,
                GetEnumValueExpression(enum_value)
            );
        }

        full_enum << enum_footer.str();
        return full_enum.str();
    }

    std::string CodeBuilder::BuildStructDefinition(
        std::string_view struct_name,
        const std::vector<Declaration>& fields)
    {
        std::ostringstream full_struct {};
        auto [struct_header, _, struct_footer] = BuildStartOfDefinition(
            EDL_STRUCT_KEYWORD,
            struct_name,
            c_type_definition_tab_count);

        // Add top level struct attributes
        full_struct << std::format(c_struct_attributes, struct_name);
        full_struct << struct_header.str();

        for (auto& field : fields)
        {
            bool is_array = !field.m_array_dimensions.empty();
            bool is_struct_or_wstring =
                field.IsEdlType(EdlTypeKind::Struct) ||
                field.IsEdlType(EdlTypeKind::WString);

            if (!is_array && is_struct_or_wstring)
            {
                // The flatbuffer generated type will be Box<T> where T is the flatbuffer representation.
                // We need to add this attribute so the edlcodegen-macro crate knows how to convert the field.
                full_struct << std::format("\n{}#[boxed_target]\n", c_four_spaces);
            }

            if (field.IsEdlType(EdlTypeKind::Optional))
            {
                auto inner_type = field.m_edl_type_info.inner_type;
                if (inner_type->m_type_kind == EdlTypeKind::Struct)
                {
                    // The flatbuffer generated type will be Option<Box<T>> where T is the flatbuffer representation.
                    // We need to add this attribute so the edlcodegen-macro crate knows how to convert the field.
                    full_struct << std::format("\n{}#[boxed_inner_target]\n", c_four_spaces);
                }
            }

            auto struct_field = std::format("pub {}: {}", field.m_name, GetFullDeclarationType(field));
            full_struct << std::format("{}{},\n", c_four_spaces, struct_field);
        }

        full_struct << struct_footer.str();
        return full_struct.str();
    }

    std::string CodeBuilder::GenerateFlatbuffersWrapperModuleFile(
        std::string_view developer_namespace_name,
        std::span<const DeveloperType> abi_function_developer_types)
    {
        std::ostringstream statements {};
        for (auto& type : abi_function_developer_types)
        {
            statements << std::format(
                c_flatbuffers_pack_statement,
                type.m_name,
                type.m_name);
        }

        return std::format(
            c_flatbuffers_module_content,
            c_autogen_header_string,
            developer_namespace_name,
            statements.str());
    }
}
