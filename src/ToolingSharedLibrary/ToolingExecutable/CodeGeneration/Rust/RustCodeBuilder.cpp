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
            developer_namespace_name,
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
            developer_namespace_name,
            types_module.str());
    }

    Definition CodeBuilder::BuildStartOfDefinition(
        std::string_view type_name,
        std::string_view identifier_name,
        std::size_t num_of_tabs)
    {
        Definition definition{};
        definition.m_header << std::format("pub {} {} {}\n", type_name, identifier_name, LEFT_CURLY_BRACKET);
        definition.m_footer << std::format("{}\n", RIGHT_CURLY_BRACKET);

        return definition;
    }

    std::string CodeBuilder::BuildEnumDefinition(
        std::string_view developer_namespace_name,
        const DeveloperType& developer_types)
    {
        std::ostringstream full_enum{};

        auto [enum_header, _, enum_footer] = BuildStartOfDefinition(
            "enum",
            developer_types.m_name,
            c_type_definition_tab_count
        );

        // Add top level enum attributes
        full_enum << std::format(c_enum_attributes, developer_namespace_name, developer_types.m_name);
        full_enum  << enum_header.str();
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
        std::string_view developer_namespace_name,
        const std::vector<Declaration>& fields)
    {
        std::ostringstream full_struct {};
        auto [struct_header, _, struct_footer] = BuildStartOfDefinition(
            EDL_STRUCT_KEYWORD,
            struct_name,
            c_type_definition_tab_count);

        // Add top level struct attributes
        full_struct << std::format(c_struct_attributes, developer_namespace_name, struct_name);
        full_struct << struct_header.str();
        
        for (auto& field : fields)
        {
            bool is_array = !field.m_array_dimensions.empty();
            bool is_struct_or_wstring = 
                field.IsEdlType(EdlTypeKind::Struct) || 
                field.IsEdlType(EdlTypeKind::WString);
            
            if (!is_array && is_struct_or_wstring)
            {
                // Add attribute for plain struct fields to direct edlcodegen-macro's flatbuffer
                // conversion functions.
                full_struct << std::format("\n{}#[boxed_target]\n", c_four_spaces);
            }

            if (field.IsEdlType(EdlTypeKind::Optional))
            {
                auto inner_type = field.m_edl_type_info.inner_type;
                if (inner_type->m_type_kind == EdlTypeKind::Struct)
                {
                    // Add attribute for optional struct fields to direct edlcodegen-macro's
                    // flatbuffer conversion functions.
                    full_struct << std::format("\n{}#[boxed_inner_target]\n", c_four_spaces);
                }
            }

            auto struct_field = std::format("pub {}: {}", field.m_name, GetFullDeclarationType(field));
            full_struct << std::format("{}{},\n",c_four_spaces, struct_field);
        }

        full_struct << struct_footer.str();
        return full_struct.str();
    }

    std::string CodeBuilder::GenerateFlatbuffersWrapperModuleFile(
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

    std::string CodeBuilder::BuildImplTraitModule(
        VirtualTrustLayerKind vtl_kind,
        const OrderedMap<std::string, Function>& functions)
    {
        std::ostringstream trait_functions {};
        for (auto& func : functions.values())
        {
            trait_functions << std::format(
                c_trait_func,
                func.m_name,
                GenerateFunctionParametersList(func.m_parameters),
                GetFullDeclarationType(func.m_return_info));

            trait_functions << "\n";
        }

        if (vtl_kind == VirtualTrustLayerKind::Enclave)
        {
            return std::format(c_enclave_trusted_module, c_autogen_header_string, trait_functions.str());
        }

        return std::format(c_host_untrusted_module, c_autogen_header_string, trait_functions.str());
    }

    std::string CodeBuilder::BuildStubTraitModule(
        VirtualTrustLayerKind vtl_kind,
        const OrderedMap<std::string, Function>& functions)
    {
        std::string module_str_format = c_host_trusted_module.data();
        std::string function_str_format = c_host_trusted_func.data();
        uint32_t indentation = 2;
        if (vtl_kind == VirtualTrustLayerKind::Enclave)
        {
            module_str_format = c_enclave_untrusted_module.data();
            function_str_format = c_enclave_untrusted_func.data();
            indentation = 0;
        }
           
        std::ostringstream mod_content {};
        for (auto& func : functions.values())
        {

            bool func_returns_void = func.m_return_info.IsEdlType(EdlTypeKind::Void);
            auto abi_func_returned_value_name = func_returns_void ? "_" : "result";
            auto return_statement_value = func_returns_void ? "()" : func.m_return_info.m_name;
            std::string to_flatbuffer_statements = 
                GetParamToFlatbufferStatements(indentation, func.m_parameters);

            std::string to_inout_param_statements = 
                GetReturnedDevTypeToParamStatements(indentation, func.m_parameters);

            auto abi_func_struct_name = std::format(c_function_args_struct, func.m_name);
            auto param_list = GenerateFunctionParametersList(func.m_parameters);
            auto return_type = GetFullDeclarationType(func.m_return_info);

            mod_content << FormatString(
                function_str_format,
                func.m_name,
                param_list,
                return_type,
                abi_func_struct_name,
                abi_func_struct_name,
                to_flatbuffer_statements,
                abi_func_returned_value_name,
                func.m_name,
                to_inout_param_statements,
                return_statement_value);
        }

        return FormatString(module_str_format, c_autogen_header_string, mod_content.str());
    }

    std::string CodeBuilder::BuildAbiDefinitionModule(
        VirtualTrustLayerKind vtl_kind,
        const OrderedMap<std::string, Function>& functions)
    {
        std::string abi_def_funcs_format = c_host_abi_definition_func.data();
        std::string abi_macro_format = c_define_host_funcs_macro.data();
        if (vtl_kind == VirtualTrustLayerKind::Enclave)
        {
            abi_def_funcs_format = c_enclave_abi_definition_func.data();
            abi_macro_format = c_export_enclave_funcs_macro.data();
        }

        std::ostringstream abi_functions {};
        for (auto& func : functions.values())
        {
            auto abi_func_struct_name = std::format(c_function_args_struct, func.abi_m_name);
            auto closure_statement = GetClosureFunctionStatement(func);
            abi_functions << FormatString(
                abi_def_funcs_format,
                func.abi_m_name,
                abi_func_struct_name,
                abi_func_struct_name,
                closure_statement);
        }

         auto module_content = FormatString(abi_macro_format, abi_functions.str());

         return std::format(c_abi_definitions_module, c_autogen_header_string, module_content);
    }
}
