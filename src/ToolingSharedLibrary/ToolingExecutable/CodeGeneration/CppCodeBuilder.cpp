// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once 
#include <pch.h>
#include <Edl\Structures.h>
#include <Edl\Utils.h>
#include <CodeGeneration\Contants.h>
#include <CodeGeneration\CodeGeneration.h>
#include <CodeGeneration\Flatbuffers\BuilderHelpers.h>
#include <CodeGeneration\Flatbuffers\Contants.h>
#include <sstream>

using namespace EdlProcessor;
using namespace CodeGeneration::Flatbuffers;

namespace CodeGeneration
{
    std::string CppCodeBuilder::BuildDeveloperTypesHeader(
        std::string_view developer_namespace_name,
        std::span<const DeveloperType> developer_types_insertion_list)
    {
        std::ostringstream types_header {};
        std::ostringstream enums_definitions {};
        std::ostringstream struct_declarations {};

        for (auto& type : developer_types_insertion_list)
        {
            if (type.IsEdlType(EdlTypeKind::Enum) || type.IsEdlType(EdlTypeKind::AnonymousEnum))
            {
                enums_definitions << BuildEnumDefinition(type);
            }
            else
            {
                struct_declarations << std::format(c_statements_for_developer_struct, type.m_name);
            }
        }

        types_header << struct_declarations.str() << enums_definitions.str();

        for (auto& type : developer_types_insertion_list)
        {
            if (type.IsEdlType(EdlTypeKind::Struct))
            {
                types_header << BuildStructDefinition(type.m_name, type.m_fields);
            }
        }

        return std::format(
            c_developer_types_file,
            c_autogen_header_string,
            developer_namespace_name,
            types_header.str());
    }

    std::string CppCodeBuilder::BuildAbiTypesHeader(
        std::string_view developer_namespace_name,
        std::string_view sub_folder_name,
        std::span<const DeveloperType> abi_function_developer_types)
    {
        std::ostringstream types_header {};

        for (auto& type : abi_function_developer_types)
        {
            types_header << BuildStructDefinition(type.m_name, type.m_fields);
        }

        return std::format(
            c_abi_function_types_file,
            c_autogen_header_string,
            sub_folder_name,
            sub_folder_name,
            developer_namespace_name,
            developer_namespace_name,
            types_header.str());
    }


    std::string CppCodeBuilder::BuildAbiTypesMetadataHeader(
        std::string_view developer_namespace_name,
        std::string_view sub_folder_name,
        std::span<const DeveloperType> developer_types_insertion_list,
        std::span<const DeveloperType> abi_function_developer_types)
    {
        std::ostringstream struct_metadata {};

        for (auto& type : developer_types_insertion_list)
        {
            if (type.IsEdlType(EdlTypeKind::Struct))
            {
                struct_metadata << BuildStructMetaData(developer_namespace_name, "Types", type.m_name, type.m_fields);
            }
        }

        for (auto& type : abi_function_developer_types)
        {
            struct_metadata << BuildStructMetaData(developer_namespace_name, "Abi::Types", type.m_name, type.m_fields);
        }

        struct_metadata << std::format(
            c_abi_flatbuffer_register_callbacks_metadata,
            developer_namespace_name,
            developer_namespace_name);

        return std::format(
            c_abi_struct_metadata_file,
            c_autogen_header_string,
            sub_folder_name,
            struct_metadata.str());
    }

    std::string GenerateTabs(std::size_t count)
    {
        // User 4 spaces as tabs
        std::string spaces {};
        while (count > 0)
        {
            spaces += c_four_spaces;
            count--;
        }

        return spaces;
    }

    CppCodeBuilder::Definition CppCodeBuilder::BuildStartOfDefinition(
        std::string_view type_name,
        std::string_view identifier_name,
        std::size_t num_of_tabs)
    {
        CppCodeBuilder::Definition definition{};
        auto spaces = GenerateTabs(num_of_tabs);
        if (identifier_name.empty())
        {
            
            definition.m_header << std::format("{}{}", spaces, type_name);
        }
        else
        {
            definition.m_header << std::format("{}{} {}", spaces, type_name, identifier_name);
        }

        definition.m_body << std::format("\n{}{}\n", spaces, LEFT_CURLY_BRACKET);
        definition.m_footer << std::format("{}{}{}\n", spaces, RIGHT_CURLY_BRACKET, SEMI_COLON);

        return definition;
    }

    std::string CppCodeBuilder::BuildEnumDefinition(const DeveloperType& developer_types)
    {
        if (developer_types.m_items.empty())
        {
            return {};
        }

        auto is_named_enum = (developer_types.m_type_kind == EdlTypeKind::Enum);
        std::string enum_name = (is_named_enum) ? developer_types.m_name : "";

        auto [enum_header, enum_body, enum_footer] = BuildStartOfDefinition(
            EDL_ENUM_KEYWORD,
            enum_name, 
            c_type_definition_tab_count);

        auto body_tab_count = GenerateTabs(2);

        for (auto& [enum_value_name, enum_value] : developer_types.m_items)
        {
            if (enum_value.m_value)
            {
                // Value was the enum name for a value within the anonymous enum.
                Token value_token = enum_value.m_value.value();
                enum_body << std::format("{}{} = {},\n", body_tab_count, enum_value_name, value_token.ToString());
            }
            else if (enum_value.m_is_hex)
            {
                auto hex_value = uint64_to_hex(enum_value.m_declared_position);
                enum_body << std::format("{}{} = {},\n", body_tab_count, enum_value_name, hex_value);
            }
            else
            {
                auto decimal_value = uint64_to_decimal(enum_value.m_declared_position);
                enum_body << std::format("{}{} = {},\n", body_tab_count, enum_value_name, decimal_value);
            }
        }

        return std::format("\n{}{}{}", enum_header.str(), enum_body.str(), enum_footer.str());
    }

    std::string CppCodeBuilder::BuildStructField(
        const Declaration& declaration)
    {
        return std::format("{} {}", GetFullDeclarationType(declaration), declaration.m_name);
    }

    std::string CppCodeBuilder::BuildStructDefinition(
        std::string_view struct_name,
        const std::vector<Declaration>& fields)
    {
        auto [struct_header, struct_body, struct_footer] = BuildStartOfDefinition(
            EDL_STRUCT_KEYWORD,
            struct_name,
            c_type_definition_tab_count);

        auto body_tab_count = GenerateTabs(2);

        for (auto& field : fields)
        {
            struct_body << std::format(
                "{}{} {{}}{}\n",
                body_tab_count,
                BuildStructField(field),
                SEMI_COLON);
        }

        return std::format("\n{}{}{}",
            struct_header.str(),
            struct_body.str(),
            struct_footer.str());
    }

    std::string CppCodeBuilder::BuildStructMetaData(
        std::string_view generated_parent_namespace,
        std::string_view generated_sub_namespace,
        std::string_view struct_name,
        const std::vector<Declaration>& fields)
    {
        std::ostringstream devtype_field_ptrs{};
        std::ostringstream flatbuffer_field_ptrs {};

        for (size_t i = 0; i < fields.size(); i++)
        {
            auto separator = ( i + 1 != fields.size()) ? "," : "";
            auto& field = fields[i];

            devtype_field_ptrs << std::format(
                c_struct_metadata_field_ptr,
                generated_parent_namespace,
                generated_sub_namespace,
                struct_name,
                field.m_name,
                separator);

            flatbuffer_field_ptrs << std::format(
                c_flatbuffer_field_ptr,
                generated_parent_namespace,
                struct_name,
                field.m_name,
                separator);
        }

        std::string struct_in_dev_type_namespace = std::format(
            "{}::{}::{}",
            generated_parent_namespace,
            generated_sub_namespace,
            struct_name);

        std::ostringstream struct_metadata {};
        struct_metadata << std::format(
            c_struct_meta_data_outline,
            struct_in_dev_type_namespace,
            devtype_field_ptrs.str());

        std::string struct_in_flatbuffer_namespace = std::format(
            "{}::FlatbufferTypes::{}T",
            generated_parent_namespace,
            struct_name);

        std::ostringstream flatbuffer_metadata {};
        flatbuffer_metadata << std::format(
            c_struct_meta_data_outline,
            struct_in_flatbuffer_namespace,
            flatbuffer_field_ptrs.str());
        
        struct_metadata << flatbuffer_metadata.str();

        return struct_metadata.str();
    }

    std::string CppCodeBuilder::BuildFunctionParameters(
       const Function& function,
       const FunctionParametersInfo& param_info)
    {
        std::ostringstream function_parameters;
        function_parameters << "(";

        for (auto i = 0U; i < function.m_parameters.size(); i++)
        {
            const Declaration& declaration = function.m_parameters[i];
            auto partially_complete_parameter = GetParameterForFunction(declaration);
            auto complete_parameter = AddSalToParameter(declaration, partially_complete_parameter);

            if (i + 1U < function.m_parameters.size())
            {
                function_parameters << std::format("{}{} ", complete_parameter, COMMA);
            }
            else
            {
                function_parameters << std::format("{}", complete_parameter);
            }
        }

        function_parameters << ")";

        return function_parameters.str();
    }

    std::string CppCodeBuilder::BuildTrustBoundaryFunction(
        std::string_view developer_namespace_name,
        const Function& function,
        std::string_view abi_function_to_call,
        bool is_vtl0_callback,
        const FunctionParametersInfo& param_info)
    {
        std::string function_params_struct_type = std::format(c_function_args_struct, function.abi_m_name);

        std::string inner_body = std::format(
            c_inner_abi_function,
            developer_namespace_name,
            function_params_struct_type,
            function_params_struct_type,
            is_vtl0_callback ? "" : c_enforce_memory_restriction_call,
            abi_function_to_call);

        return std::format(
            c_outer_abi_function,
            c_static_void_ptr,
            function.abi_m_name,
            inner_body);
    }
    
    CppCodeBuilder::FunctionParametersInfo CppCodeBuilder::GetInformationAboutParameters(const Function& function)
    {
        FunctionParametersInfo param_info {};
        size_t in_out_index = 0U;
        size_t out_index = 0U;

        for (size_t params_index = 0U; params_index < function.m_parameters.size(); params_index++)
        {
            const Declaration& declaration = function.m_parameters[params_index];

            // These will be copied into the flatbuffer. For Out param std::arrays we need to make sure the flatbuffer vector 
            // that is created is of size std::array<T, N>::size() and not 0/empty so we keep the invariant that the vector.size() will always
            // be equal to array.size() before passing the flatbuffer through the abi.
            if (!declaration.IsOutParameterOnly() || 
                (declaration.IsOutParameterOnly() && !declaration.m_array_dimensions.empty()))
            {
                param_info.m_param_to_convert_names << std::format(
                    c_parameter_conversion_statement,
                    declaration.m_name,
                    declaration.m_name,
                    declaration.m_name);
            }

            if (!declaration.IsInParameterOnly())
            {
                in_out_index = declaration.IsInOutParameter() ? in_out_index + 1 : in_out_index;
                out_index = declaration.IsOutParameterOnly() ? out_index + 1 : out_index;
                param_info.m_copy_values_from_out_struct_to_original_args << std::format(
                    c_update_inout_and_out_param_statement,
                    declaration.m_name,
                    declaration.m_name);
            }
        }

        param_info.m_function_return_value = GetFullDeclarationType(function.m_return_info);
        auto& return_info = function.m_return_info.m_edl_type_info;
        bool is_void_function = return_info.m_type_kind == EdlTypeKind::Void;
        param_info.m_are_return_params_needed = !is_void_function || in_out_index > 0 || out_index > 0;
        param_info.m_function_return_type_void = is_void_function;

        return param_info;
    }

    std::string CppCodeBuilder::BuildStubFunction(
        std::string_view developer_namespace_name,
        const Function& function,
        DataDirectionKind direction,
        std::string_view cross_boundary_func_name,
        const FunctionParametersInfo& param_info)
    {
        bool forwarding_from_vtl0_to_vtl1 = direction == DataDirectionKind::Vtl0ToVtl1;
        std::string inline_part = forwarding_from_vtl0_to_vtl1 ? "" : "inline ";

        auto function_declaration = std::format(
            "{}{} {}{}",
            inline_part,
            param_info.m_function_return_value,
            function.m_name,
            BuildFunctionParameters(function, param_info));

        std::string function_params_struct_type = std::format(c_function_args_struct, function.abi_m_name);
        std::ostringstream function_body {};
        function_body << std::format(c_pack_params_to_flatbuffer_call, function_params_struct_type);
        function_body << param_info.m_param_to_convert_names.str();

        std::string return_statement {};

        if (!param_info.m_function_return_type_void)
        {
            return_statement = c_return_value_back_to_initial_caller_with_move;
        }

        std::string final_part_of_function {};

        if (param_info.m_are_return_params_needed)
        {
            // Move all values out of the return struct and into their in-out/out function parameter counterpart.
            std::ostringstream copy_statements_for_return_struct;
            copy_statements_for_return_struct 
                << param_info.m_copy_values_from_out_struct_to_original_args.str()
                << return_statement;

            final_part_of_function = copy_statements_for_return_struct.str();
        }
        else
        {
            // no in-out/out parameters to copy out of the return struct.
            final_part_of_function = return_statement;
        }

        if (param_info.m_function_return_type_void)
        {
            if (forwarding_from_vtl0_to_vtl1)
            {
                function_body << std::format(c_vtl0_call_to_vtl1_export, cross_boundary_func_name);
            }
            else
            {
                function_body << std::format(c_vtl1_call_to_vtl0_callback, cross_boundary_func_name);
            }
        }
        else
        {
            if (forwarding_from_vtl0_to_vtl1)
            {
                function_body << std::format(
                    c_vtl0_call_to_vtl1_export_with_return,
                    developer_namespace_name,
                    function_params_struct_type,
                    cross_boundary_func_name);
            }
            else
            {
                function_body << std::format(
                    c_vtl1_call_to_vtl0_callback_with_return,
                    developer_namespace_name,
                    function_params_struct_type,
                    cross_boundary_func_name);
            }
        }
       
        function_body << final_part_of_function;

        return std::format(
            c_stub_function_body,
            function_declaration,
            function_body.str());
    }

    CppCodeBuilder::HostToEnclaveContent CppCodeBuilder::BuildHostToEnclaveFunctions(
        std::string_view generated_namespace,
        std::span<Function> functions)
    {
        std::ostringstream vtl1_abi_functions {};
        vtl1_abi_functions << c_vtl1_enforce_mem_restriction_func;
        std::ostringstream vtl1_abi_impl_functions {};
        std::ostringstream vtl1_trusted_function_declarations {};
        std::ostringstream vtl0_stubs_for_vtl1_trusted_functions {};

        for (auto& function : functions)
        {
            auto param_info = GetInformationAboutParameters(function);
            auto vtl1_exported_func_name = std::format(c_generated_stub_name, function.abi_m_name);

            // This is the vtl0 stub function the developer will call into to start the flow
            // of calling their vtl1 enclave function impl.
            vtl0_stubs_for_vtl1_trusted_functions << BuildStubFunction(
                generated_namespace,
                function,
                DataDirectionKind::Vtl0ToVtl1,
                vtl1_exported_func_name,
                param_info);

            auto vtl1_call_to_vtl1_export = std::format(
                c_vtl1_call_to_vtl1_export,
                function.m_name,
                function.m_name);

            // This is the vtl0 function that is exported by the enclave and called via a
            // CallEnclave call by the abi.
            vtl1_abi_functions << BuildTrustBoundaryFunction(
                generated_namespace,
                function,
                vtl1_call_to_vtl1_export,
                false,
                param_info);

            // VTL1 enclave function that the developer will implement. It is called by the vtl1
            // abi function impl for this particular function.
            vtl1_trusted_function_declarations << std::format(
                c_function_declaration,
                param_info.m_function_return_value,
                function.m_name,
                BuildFunctionParameters(function, param_info));
        }

        HostToEnclaveContent content {};
        content.m_vtl0_trusted_stub_functions = vtl0_stubs_for_vtl1_trusted_functions.str();
        content.m_vtl1_trusted_function_declarations = vtl1_trusted_function_declarations.str();
        std::string callbacks_name = std::format(
            c_vtl1_register_callbacks_abi_export_name,
            generated_namespace);

        vtl1_abi_functions << std::format(
            c_vtl1_register_callbacks_abi_export,
            callbacks_name);

        content.m_vtl1_abi_functions = vtl1_abi_functions.str();

        return content;
    }

    CppCodeBuilder::EnclaveToHostContent CppCodeBuilder::BuildEnclaveToHostFunctions(
        std::string_view generated_namespace,
        std::string_view generated_class_name,
        std::span<Function> functions)
    {
        size_t number_of_functions = functions.size();
        size_t number_of_functions_plus_allocators = functions.size() + c_number_of_abi_callbacks;
        std::ostringstream vtl0_abi_boundary_functions {};
        std::ostringstream vtl0_developer_declaration_functions {};
        std::ostringstream vtl1_stubs_for_vtl0_untrusted_functions {};

        // Add allocate vtl0 memory function from ABI base file.
        std::ostringstream vtl0_class_method_addresses;
        vtl0_class_method_addresses << c_allocate_memory_callback_to_address.data();
        vtl0_class_method_addresses << c_deallocate_memory_callback_to_address.data();
        std::ostringstream vtl0_class_method_names;
        vtl0_class_method_names << c_allocate_memory_callback_to_name.data();
        vtl0_class_method_names << c_deallocate_memory_callback_to_name.data();

        for (auto& function : functions)
        {
            auto param_info = GetInformationAboutParameters(function);

            auto generated_callback_in_namespace = std::format(
               c_generated_callback_in_namespace,
               generated_namespace,
               function.abi_m_name);

            // This is the vtl1 untrusted stub function that the developer will call into from vtl1 with the
            // same parameters as their vtl0 untrusted impl function. This initiates the abi call from vtl1 
            // to the vtl0 abi boundary function for this specific function.
            vtl1_stubs_for_vtl0_untrusted_functions << BuildStubFunction(
                generated_namespace,
                function,
                DataDirectionKind::Vtl1ToVtl0,
                generated_callback_in_namespace,
                param_info);

            auto vtl0_call_to_vtl0_callback = std::format(
                c_vtl0_call_to_vtl0_callback,
                function.m_name,
                function.m_name);

            // This is the vtl0 callback that will call into our abi vtl0 callback implementation.
            // This callback is what vtl1 will call with CallEnclave.
            vtl0_abi_boundary_functions << BuildTrustBoundaryFunction(
                generated_namespace,
                function,
                vtl0_call_to_vtl0_callback,
                true,
                param_info);

            // This is the developers vtl0 impl function. The developer will implement this static class
            // method.
            vtl0_developer_declaration_functions << std::format(
                c_function_declaration,
                param_info.m_function_return_value,
                function.m_name,
                BuildFunctionParameters(function, param_info));

            // capture the addresses for each developer callback so we can pass them to vtl1 later.
            vtl0_class_method_addresses << std::format(
                c_callback_to_address,
                function.abi_m_name);

            vtl0_class_method_names << std::format(
                c_callback_to_name,
                generated_callback_in_namespace);
        }

        EnclaveToHostContent content {};

        // This is the array of callbacks addresses that will be passed to vtl1 with the abi's register
        // callbacks functions, that we export from the enclave dll.
        content.m_vtl0_untrusted_abi_stubs_address_info = std::format(
            c_vtl0_untrusted_abi_stubs_address_info,
            number_of_functions_plus_allocators,
            vtl0_class_method_addresses.str(),
            number_of_functions_plus_allocators,
            vtl0_class_method_names.str());

        content.m_vtl0_untrusted_function_declarations = vtl0_developer_declaration_functions.str();
        content.m_vtl0_abi_functions = vtl0_abi_boundary_functions.str();
        content.m_vtl1_stubs_for_vtl0_untrusted_functions = vtl1_stubs_for_vtl0_untrusted_functions.str();

        return content;
    }

    std::string CppCodeBuilder::BuildVtl1ExportedFunctionsSourcefile(
        std::string_view generated_namespace_name,
        std::span<Function> developer_functions_to_export)
    {
        std::ostringstream exported_definitions {};
        std::ostringstream pragma_link_statements {};

        for (auto& function : developer_functions_to_export)
        {
            auto generated_func_name = std::format(c_generated_stub_name_no_quotes, function.abi_m_name);
            exported_definitions << std::format(
                c_enclave_export_func_definition,
                generated_func_name,
                generated_namespace_name,
                generated_func_name);

            pragma_link_statements << std::format(c_vtl1_sdk_pragma_statement, generated_func_name);
        }

        auto register_callbacks_name = std::format(c_vtl1_register_callbacks_abi_export_name, generated_namespace_name);

        exported_definitions << std::format(
                c_enclave_export_func_definition,
                register_callbacks_name,
                generated_namespace_name,
                register_callbacks_name);

        pragma_link_statements << std::format(c_vtl1_sdk_pragma_statement, register_callbacks_name);

        return std::format(
            c_vtl1_export_functions_source_file,
            c_autogen_header_string,
            pragma_link_statements.str(),
            exported_definitions.str());
    }
}
