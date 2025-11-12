// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once 
#include <pch.h>
#include <Edl\Structures.h>
#include <Edl\Utils.h>
#include <CodeGeneration\Rust\Constants.h>
#include <CodeGeneration\Rust\CodeGeneration.h>
#include <CodeGeneration\Flatbuffers\BuilderHelpers.h>
#include <CodeGeneration\Flatbuffers\Constants.h>
#include <sstream>

using namespace EdlProcessor;
using namespace CodeGeneration::Flatbuffers;

namespace CodeGeneration::Rust
{
    std::string CodeBuilder::GenerateDeveloperTypesModuleFile(
        std::string_view developer_namespace_name,
        const OrderedMap<std::string, DeveloperType>& developer_types_map)
    {
        std::ostringstream types_module{};
        std::ostringstream enums_definitions{};
        std::ostringstream anon_enums_constants{};
        std::ostringstream struct_declarations{};

        for (auto& type : developer_types_map.values())
        {
            if (type.IsEdlType(EdlTypeKind::Enum))
            {
                enums_definitions << BuildEnumDefinition(developer_namespace_name, type);
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
                types_module << BuildStructDefinition(type.m_name, developer_namespace_name, type.m_fields);
            }
        }

        return std::format(
            c_dev_types_file,
            c_autogen_header_string,
            types_module.str());
    }

    std::string CodeBuilder::GenerateAbiTypesModuleFile(
        std::string_view developer_namespace_name,
        std::span<const DeveloperType> abi_function_developer_types)
    {
        std::ostringstream types_module{};

        for (auto& type : abi_function_developer_types)
        {
            types_module << BuildStructDefinition(type.m_name, developer_namespace_name, type.m_fields);
        }

        return std::format(
            c_abi_function_types_file,
            c_autogen_header_string,
            types_module.str());
    }

    Definition CodeBuilder::BuildStartOfDefinition(
        std::string_view type_name,
        std::string_view identifier_name,
        std::size_t num_of_tabs)
    {
        Definition definition{};
        auto spaces = GenerateTabs(num_of_tabs);
        definition.m_header << std::format("{}pub {} {} {}", spaces, type_name, identifier_name, LEFT_CURLY_BRACKET);
        definition.m_body << std::format("\n{}", spaces);
        definition.m_footer << std::format("{}{}\n", spaces, RIGHT_CURLY_BRACKET);

        return definition;
    }

    std::string CodeBuilder::BuildEnumDefinition(
        std::string_view developer_namespace_name,
        const DeveloperType& developer_types)
    {
        std::ostringstream enum_with_repr{};

        auto [enum_header, enum_body, enum_footer] = BuildStartOfDefinition(
            "enum",
            developer_types.m_name,
            c_type_definition_tab_count
        );

        enum_with_repr << "#[repr(C, u32)]\n";

        // Add top level enum attributes
        enum_with_repr << std::format(c_type_attributes, "enum", developer_namespace_name, developer_types.m_name);

        const auto body_tab_count = GenerateTabs(1);
        enum_with_repr << enum_header.str();
        enum_body << std::format("{}#[default]\n", body_tab_count);

        for (auto& enum_value : developer_types.m_items.values())
        {
            enum_body << std::format(
                "{}{} = {},\n",
                body_tab_count,
                enum_value.m_name,
                GetEnumValueExpression(enum_value)
            );
        }

        return std::format("\n{}{}{}", enum_with_repr.str(), enum_body.str(), enum_footer.str());
    }

    std::string CodeBuilder::BuildStructDefinition(
        std::string_view struct_name,
        std::string_view developer_namespace_name,
        const std::vector<Declaration>& fields)
    {
        auto [struct_header, struct_body, struct_footer] = BuildStartOfDefinition(
            EDL_STRUCT_KEYWORD,
            struct_name,
            c_type_definition_tab_count);

        auto body_tab_count = GenerateTabs(1);

        // Add top level struct attributes
        struct_header << std::format(c_type_attributes, "struct", developer_namespace_name, struct_name);

        for (auto& field : fields)
        {
            if (field.IsEdlType(EdlTypeKind::Optional))
            {
                auto inner_type = field.m_edl_type_info.inner_type;
                if (inner_type->m_type_kind == EdlTypeKind::Struct)
                {
                    // Add attribute for optional struct fields to direct edlcodegen-macro's
                    // flatbuffer conversion functions.
                    struct_body << std::format("\n{}#[boxed_inner_target]\n", body_tab_count);
                }
            }
            else if (field.IsEdlType(EdlTypeKind::Struct) || field.IsEdlType(EdlTypeKind::WString))
            {
                // Add attribute for plan struct fields to direct edlcodegen-macro's flatbuffer
                // conversion functions.
                struct_body << std::format("\n{}#[boxed_target]\n", body_tab_count);
            }

            auto struct_field = std::format("{} {}", GetFullDeclarationType(field), field.m_name);
            struct_body << std::format("{}{},\n",body_tab_count, struct_field);
        }

        return std::format("\n{}{}{}",
            struct_header.str(),
            struct_body.str(),
            struct_footer.str());
    }

    std::string CodeBuilder::GenerateFlatbuffersPackModuleFile(
        std::string_view developer_namespace_name,
        std::span<const DeveloperType> abi_function_developer_types)
    {
        std::ostringstream statements{};
        for (auto& type : abi_function_developer_types)
        {
            statements << std::format(
                c_flatbuffers_pack_statement,
                developer_namespace_name,
                type.m_name,
                developer_namespace_name,
                type.m_name);
        }

        return std::format(
            c_flatbuffers_module_content,
            c_autogen_header_string,
            statements.str());
    }
}
