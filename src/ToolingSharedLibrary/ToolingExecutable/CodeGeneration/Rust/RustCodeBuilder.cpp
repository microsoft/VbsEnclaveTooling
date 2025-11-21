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

        EdlCrateInfo crate_info = GetEdlCrateInfo(vtl_kind);

        return std::format(
            c_dev_types_file,
            c_autogen_header_string,
            crate_info.m_alloc_imports,
            developer_namespace_name,
            crate_info.m_crate_name,
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

        EdlCrateInfo crate_info = GetEdlCrateInfo(vtl_kind);

        return std::format(
            c_abi_function_types_file,
            c_autogen_header_string,
            crate_info.m_alloc_imports,
            developer_namespace_name,
            crate_info.m_crate_name,
            types_module.str(),
            crate_info.m_vec_import);
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
        VirtualTrustLayerKind vtl_kind,
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

        auto crate_info = GetEdlCrateInfo(vtl_kind);
        return std::format(
            c_flatbuffers_module_content,
            c_autogen_header_string,
            crate_info.m_crate_name,
            crate_info.m_crate_name,
            developer_namespace_name,
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
                c_trait_function,
                func.m_name,
                GenerateFunctionParametersList(func.m_parameters),
                GetFullDeclarationType(func.m_return_info));

            trait_functions << "\n";
        }

        if (vtl_kind == VirtualTrustLayerKind::Enclave)
        {
            return std::format(c_enclave_trusted_module_outline, c_autogen_header_string, trait_functions.str());
        }

        return std::format(c_host_untrusted_module_outline, c_autogen_header_string, trait_functions.str());
    }

    std::string CodeBuilder::BuildStubTraitModule(
        VirtualTrustLayerKind vtl_kind,
        std::string_view stub_class_name,
        std::string_view developer_namespace_name,
        const OrderedMap<std::string, Function>& functions)
    {
        std::string function_str_format = c_host_trusted_function.data();
        uint32_t indentation = 2;
        if (vtl_kind == VirtualTrustLayerKind::Enclave)
        {
            function_str_format = c_enclave_untrusted_function.data();
            indentation = 1;
        }

        std::ostringstream mod_content {};
        for (auto& func : functions.values())
        {

            bool func_returns_void = func.m_return_info.IsEdlType(EdlTypeKind::Void);
            auto abi_func_returned_value_name = func_returns_void ? "_" : "result";
            std::string return_statement_value = "()";

            if (!func_returns_void)
            { 
                return_statement_value = std::format("result.m_{}", func.m_return_info.m_name);
            }

            std::string to_flatbuffer_statements =
                GetCloneToAbiStructStatements(indentation, func.m_parameters);

            std::string to_inout_param_statements =
                GetMoveFromAbiStructToParamStatements(indentation, func.m_parameters);

            auto abi_func_struct_name = std::format(c_function_args_struct, func.abi_m_name);
            auto param_list = GenerateFunctionParametersList(func.m_parameters);
            auto return_type = GetFullDeclarationType(func.m_return_info);
            auto abi_stub_func_name = std::format(c_generated_stub_name_no_quotes, func.abi_m_name);

            mod_content << FormatString(
                function_str_format,
                func.m_name,
                param_list,
                return_type,
                abi_func_struct_name,
                abi_func_struct_name,
                to_flatbuffer_statements,
                abi_func_returned_value_name,
                abi_stub_func_name,
                to_inout_param_statements,
                return_statement_value);
        }
        
        if (vtl_kind == VirtualTrustLayerKind::HostApp)
        {
            auto register_callbacks_function = std::format(
                c_vtl1_register_callbacks_abi_export_name,
                developer_namespace_name);

            return std::format(
                c_host_trusted_module_outline,
                c_autogen_header_string,
                developer_namespace_name,
                stub_class_name,
                stub_class_name,
                mod_content.str(),
                register_callbacks_function);
        }

        return std::format(
            c_enclave_untrusted_module_outline,
            c_autogen_header_string,
            developer_namespace_name,
            mod_content.str());
    }

    std::string CodeBuilder::BuildAbiDefinitionModule(
        VirtualTrustLayerKind vtl_kind,
        std::string_view trait_name,
        std::string_view generated_namespace_name,
        const OrderedMap<std::string, Function>& functions)
    {
        std::ostringstream abi_functions {};
        for (auto& func : functions.values())
        {
            auto abi_func_struct_name = std::format(c_function_args_struct, func.abi_m_name);
            auto closure_statement = GetClosureFunctionStatement(func, vtl_kind, trait_name);
            auto abi_function_name = std::format(c_generated_stub_name_no_quotes, func.abi_m_name);

            if (vtl_kind == VirtualTrustLayerKind::HostApp)
            {
                abi_functions << std::format(
                    c_host_abi_definition_function,
                    abi_function_name,
                    abi_func_struct_name,
                    generated_namespace_name,
                    abi_func_struct_name,
                    closure_statement);
            }
            else
            {
                abi_functions << std::format(
                    c_enclave_abi_definition_function,
                    abi_function_name,
                    abi_func_struct_name,
                    abi_func_struct_name,
                    closure_statement);
            }
        }

        if (vtl_kind == VirtualTrustLayerKind::HostApp)
        {
            auto [names, addresses, total] = GetRegisterCallbacksFunctionStatements(functions);
            auto macro_info = std::format(
                c_define_host_functions_macro,
                abi_functions.str(),
                total,
                names,
                total,
                addresses);
            
            return std::format(c_abi_definitions_module_outline, c_autogen_header_string, macro_info);
        }

        auto register_callbacks_function = std::format(
            c_vtl1_register_callbacks_abi_export_name,
            generated_namespace_name);

        auto module_content = std::format(
            c_export_enclave_functions_macro,
            generated_namespace_name,
            abi_functions.str(),
            register_callbacks_function);

        return std::format(c_abi_definitions_module_outline, c_autogen_header_string, module_content);
    }
}
