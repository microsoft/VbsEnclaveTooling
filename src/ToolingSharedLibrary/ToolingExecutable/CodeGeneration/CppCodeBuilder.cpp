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
    std::string CppCodeBuilder::BuildTypesHeader(
        const std::vector<DeveloperType>& developer_types_insertion_list,
        const std::vector<DeveloperType>& abi_function_developer_types)
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

        types_header << struct_declarations.str();
        types_header << enums_definitions.str();
        std::ostringstream struct_metadata {};

        for (auto& type : developer_types_insertion_list)
        {
            if (type.IsEdlType(EdlTypeKind::Struct))
            {
                types_header << BuildStructDefinition(type.m_name, type.m_fields);
                struct_metadata << BuildStructMetaData(type.m_name, type.m_fields);
            }
        }

        for (auto& type : abi_function_developer_types)
        {
            types_header << BuildStructDefinition(type.m_name, type.m_fields);
            struct_metadata << BuildStructMetaData(type.m_name, type.m_fields);
        }

        auto start_of_file = std::format(c_developer_types_start_of_file, c_autogen_header_string);
        auto body = std::format(c_developer_types_namespace, types_header.str(), struct_metadata.str());

        return std::format("{}{}\n", start_of_file, body);
    }

    CppCodeBuilder::Definition CppCodeBuilder::BuildStartOfDefinition(
        std::string_view type_name,
        std::string_view identifier_name)
    {
        CppCodeBuilder::Definition definition{};

        if (identifier_name.empty())
        {
            definition.m_header << std::format("{}", type_name);
        }
        else
        {
            definition.m_header << std::format("{} {}", type_name, identifier_name);
        }

        definition.m_body << std::format("\n{}\n", LEFT_CURLY_BRACKET);
        definition.m_footer << std::format("{}{}\n", RIGHT_CURLY_BRACKET, SEMI_COLON);

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

        auto [enum_header, enum_body, enum_footer] = BuildStartOfDefinition(EDL_ENUM_KEYWORD, enum_name);

        for (auto& [enum_value_name, enum_value] : developer_types.m_items)
        {
            if (enum_value.m_value)
            {
                // Value was the enum name for a value within the anonymous enum.
                Token value_token = enum_value.m_value.value();
                enum_body << std::format("{}{} = {},\n", c_four_spaces, enum_value_name, value_token.ToString());
            }
            else if (enum_value.m_is_hex)
            {
                auto hex_value = uint64_to_hex(enum_value.m_declared_position);
                enum_body << std::format("{}{} = {},\n", c_four_spaces, enum_value_name, hex_value);
            }
            else
            {
                auto decimal_value = uint64_to_decimal(enum_value.m_declared_position);
                enum_body << std::format("{}{} = {},\n", c_four_spaces, enum_value_name, decimal_value);
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
            struct_name);

        for (auto& field : fields)
        {
            struct_body << std::format(
                "{}{} {{}}{}\n",
                c_four_spaces,
                BuildStructField(field),
                SEMI_COLON);
        }

        return std::format("\n{}{}{}",
            struct_header.str(),
            struct_body.str(),
            struct_footer.str());
    }

    std::string CppCodeBuilder::BuildStructMetaData(
        std::string_view struct_name,
        const std::vector<Declaration>& fields)
    {
        if (fields.empty())
        {
            return {};
        }

        std::ostringstream devtype_field_ptrs{};
        std::ostringstream flatbuffer_field_ptrs {};

        for (size_t i = 0; i < fields.size(); i++)
        {
            auto separator = ( i + 1 != fields.size()) ? "," : "";
            auto& field = fields[i];

            devtype_field_ptrs << std::format(c_struct_metadata_field_ptr, struct_name, field.m_name, separator);
            flatbuffer_field_ptrs << std::format(c_flatbuffer_field_ptr, struct_name, field.m_name, separator);
        }

        std::string struct_in_dev_type_namespace = std::format("DeveloperTypes::{}", struct_name);
        std::ostringstream struct_metadata {};
        struct_metadata << std::format(
            c_struct_meta_data_outline,
            struct_in_dev_type_namespace,
            devtype_field_ptrs.str());

        std::string struct_in_flatbuffer_namespace = std::format("FlatbuffersDevTypes::{}T", struct_name);
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

    void AddParameterToTheForwardToDevImplList(
        const Declaration& declaration,
        std::string_view all_params_separator,
        CppCodeBuilder::FunctionParametersInfo& param_info)
    {
        // pass the actual pointer from the unique pointer to the developers impl
        // function if its not an out parameter.
        if (declaration.HasPointer() && !declaration.IsOutParameterOnly())
        {
            param_info.m_params_to_forward_to_dev_impl << FormatString(
                    "{} dev_type_params.m_{}.get()",
                    all_params_separator,
                    declaration.m_name);
        }
        else
        {
            param_info.m_params_to_forward_to_dev_impl << FormatString(
                "{} dev_type_params.m_{}",
                all_params_separator,
                declaration.m_name);
        }
    }

    std::string CppCodeBuilder::BuildTrustBoundaryFunction(
        const Function& function,
        std::string_view abi_function_to_call,
        bool is_vtl0_callback,
        const FunctionParametersInfo& param_info)
    {
        std::string function_params_struct_type = std::format(c_function_args_struct, function.abi_m_name);

        std::string inner_body = std::format(
            c_inner_abi_function,
            function_params_struct_type,
            function_params_struct_type,
            is_vtl0_callback ? "" : c_enforce_memory_restriction_call,
            abi_function_to_call);

        auto return_statement = (is_vtl0_callback) ? c_static_void_ptr : c_void_ptr;

        return std::format(
            c_outer_abi_function,
            return_statement,
            function.abi_m_name,
            inner_body);
    }
    
    CppCodeBuilder::FunctionParametersInfo CppCodeBuilder::GetInformationAboutParameters(
        const Function& function,
        const std::unordered_map<std::string, DeveloperType>& developer_types)
    {
        FunctionParametersInfo param_info {};
        size_t in_out_index = 0U;
        size_t in_index = 0U;
        size_t out_index = 0U;

        for (size_t params_index = 0U; params_index < function.m_parameters.size(); params_index++)
        {
            auto all_params_separator = (in_out_index == 0 && in_index == 0 && out_index == 0) ? "" : ",";
            const Declaration& declaration = function.m_parameters[params_index];

            AddParameterToTheForwardToDevImplList(declaration, all_params_separator, param_info);

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

            if (declaration.IsInParameterOnly())
            {
                in_index++;
            }
            else
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

    std::string CppCodeBuilder::BuildInitialCallerFunction(
        const Function& function,
        std::string_view abi_function_to_call,
        bool should_be_inline,
        const std::unordered_map<std::string, DeveloperType>& developer_types,
        const FunctionParametersInfo& param_info)
    {
        std::string inline_part = should_be_inline ? "inline " : "";

        auto function_declaration = std::format(
            "{}{} {}{}",
            inline_part,
            param_info.m_function_return_value,
            function.m_name,
            BuildFunctionParameters(function, param_info));

        std::string function_params_struct_type = std::format(c_function_args_struct, function.abi_m_name);

        // First create the using statements so we can use the type for forwarding parameters
        // and the type for returning parameters throughout the generated code.
        std::string return_parameters_using_statement = std::format(
            c_parameter_return_struct_using_statement,
            function_params_struct_type);

        std::string parameters_using_statement = std::format(
            c_pack_params_to_flatbuffer_call,
            function_params_struct_type,
            param_info.m_param_to_convert_names.str());

        std::ostringstream copy_and_using_statements;

        copy_and_using_statements << parameters_using_statement << return_parameters_using_statement;

        std::string return_statement {};

        if (!param_info.m_function_return_type_void)
        {
            return_statement = c_return_value_back_to_initial_caller_with_move;
        }

        std::string final_part_of_function {};

        if (param_info.m_are_return_params_needed)
        {
            // Copy all in-out/out values out of the return struct and into the actual reference parameter.
            std::ostringstream copy_statements_for_return_struct;
            copy_statements_for_return_struct <<
                param_info.m_copy_values_from_out_struct_to_original_args.str();

            copy_statements_for_return_struct << return_statement;

            final_part_of_function = std::format(
               c_setup_return_params_back_to_developer,
               function_params_struct_type,
               copy_statements_for_return_struct.str());
        }
        else
        {
            // no in-out/out parameters to copy out of the return struct.
            final_part_of_function = return_statement;
        }

        return std::format(
            c_initial_caller_function_body,
            function_declaration,
            copy_and_using_statements.str(),
            abi_function_to_call,
            final_part_of_function);
    }

    std::string CppCodeBuilder::BuildAbiImplFunction(
        const Function& function,
        std::string_view call_impl_str,
        const FunctionParametersInfo& param_info)
    {
        std::string function_params_struct_type = std::format(c_function_args_struct, function.abi_m_name);

        auto abi_parameters = std::format(c_abi_impl_function_parameters, function.abi_m_name);
        std::string params_to_forward = param_info.m_params_to_forward_to_dev_impl.str();
        std::ostringstream function_body {};

        std::ostringstream updated_parameters_received_from_dev_impl{};;
        
        if (param_info.m_are_return_params_needed)
        {
            updated_parameters_received_from_dev_impl << c_setup_return_params_struct;
        }
        else
        {
            updated_parameters_received_from_dev_impl
                << std::format(c_setup_no_return_params_struct, function_params_struct_type);
        }

        std::string_view abi_func_return_statement {};
        if (param_info.m_function_return_type_void)
        {
            abi_func_return_statement = c_abi_func_return_when_void;
        }
        else
        {
            abi_func_return_statement = c_abi_func_return_value;
        }

        // If we need to forward parameters to the developer impl or if we need to receive the return value
        // from the developer impl, we must instantiate the dev type struct associated with the function. If 
        // neither of those things are true (e.g function that takes no in/inout args and returns no values) then 
        // we do not generate the dev type struct variable as there is no need.
        if (!params_to_forward.empty())
        {
            function_body << std::format(c_conversion_to_dev_type_statement, function_params_struct_type);
        }
        else if (param_info.m_are_return_params_needed)
        {
            function_body << std::format(c_instantiate_dev_type, function_params_struct_type);
        }

        function_body << FormatString(
            abi_func_return_statement,
            call_impl_str,
            params_to_forward,
            updated_parameters_received_from_dev_impl.str());

        return std::format(
            c_generated_abi_impl_function,
            function.abi_m_name,
            abi_parameters,
            function_body.str());
    }

    CppCodeBuilder::HostToEnclaveContent CppCodeBuilder::BuildHostToEnclaveFunctions(
        std::string_view generated_namespace,
        const std::unordered_map<std::string, DeveloperType>& developer_types,
        std::span<Function> functions)
    {
        std::ostringstream vtl0_class_public_portion {};
        vtl0_class_public_portion << c_vtl0_enclave_class_public_keyword;

        std::ostringstream vtl1_abi_boundary_functions {};
        vtl1_abi_boundary_functions << c_vtl1_abi_boundary_functions_comment;

        std::ostringstream vtl1_abi_impl_functions {};
        vtl1_abi_impl_functions << c_vtl1_abi_impl_functions_comment;

        std::ostringstream vtl1_developer_declaration_functions {};
        vtl1_developer_declaration_functions << c_vtl1_developer_declaration_functions_comment;

        std::ostringstream vtl0_side_of_vtl1_developer_impl_functions {};
        vtl0_side_of_vtl1_developer_impl_functions << c_vtl0_side_of_vtl1_developer_impl_functions_comment;

        std::ostringstream vtl1_generated_module_exports {};

        for (auto& function : functions)
        {
            auto param_info = GetInformationAboutParameters(function, developer_types);
            auto vtl1_exported_func_name = std::format(c_generated_stub_name, function.abi_m_name);
            auto vtl0_call_to_vtl1_export = std::format(
                c_vtl0_call_to_vtl1_export,
                vtl1_exported_func_name);

            // This is the vtl0 abi function that the developer will call into to start the flow
            // of calling their vtl1 enclave function impl.
            vtl0_side_of_vtl1_developer_impl_functions << BuildInitialCallerFunction(
                function,
                vtl0_call_to_vtl1_export,
                false,
                developer_types,
                param_info);

            auto vtl1_call_to_vtl1_export = std::format(
                c_vtl1_call_to_vtl1_export,
                function.abi_m_name,
                function.abi_m_name);

            // This is the vtl0 function that is exported by the enclave and called via a
            // CallEnclave call by the abi.
            vtl1_abi_boundary_functions << BuildTrustBoundaryFunction(
                function,
                vtl1_call_to_vtl1_export,
                false,
                param_info);

            auto vtl1_dev_impl_call = std::format("VTL1_Declarations::{}", function.m_name);

            // This is the vtl1 abi function that will call the developers vtl1 function implementation.
            std::string vtl1_abi_impl_definition = BuildAbiImplFunction(
                function,
                vtl1_dev_impl_call,
                param_info);

            // VTL1 enclave function that the developer will implement. It is called by the vtl1
            // abi function impl for this particular function.
            vtl1_developer_declaration_functions << std::format(
                c_function_declaration,
                param_info.m_function_return_value,
                function.m_name,
                BuildFunctionParameters(function, param_info));

            vtl1_abi_impl_functions << vtl1_abi_impl_definition;

            vtl1_generated_module_exports << std::format(c_exported_function_in_module, function.abi_m_name);
        }

        vtl0_class_public_portion << vtl0_side_of_vtl1_developer_impl_functions.str();

        // Add register callbacks abi export to module file and add it at the end of the vtl1 stubs file.
        std::string callbacks_name = std::format(
            c_vtl1_register_callbacks_abi_export_name,
            generated_namespace);

        vtl1_generated_module_exports << callbacks_name;
        vtl1_abi_boundary_functions << std::format(
            c_vtl1_register_callbacks_abi_export,
            callbacks_name);

        auto vtl1_stubs_in_namespace =
            std::format(c_vtl1_enclave_stub_namespace, generated_namespace, vtl1_abi_boundary_functions.str());

        return HostToEnclaveContent {
            std::move(vtl0_class_public_portion),
            std::format("{}{}{}",c_autogen_header_string, c_vtl1_enclave_stub_includes, vtl1_stubs_in_namespace),
            std::move(vtl1_developer_declaration_functions),
            std::move(vtl1_abi_impl_functions)
        };
    }

    CppCodeBuilder::EnclaveToHostContent CppCodeBuilder::BuildEnclaveToHostFunctions(
        std::string_view generated_namespace,
        std::string_view generated_class_name,
        const std::unordered_map<std::string, DeveloperType>& developer_types,
        std::span<Function> functions)
    {
        size_t number_of_functions = functions.size();
        size_t number_of_functions_plus_allocators = functions.size() + c_number_of_abi_callbacks;
        std::ostringstream vtl0_class_public_functions {};
        std::ostringstream vtl0_class_private_portion {};
        vtl0_class_public_functions << c_vtl0_enclave_class_public_keyword;
        vtl0_class_private_portion << c_vtl0_enclave_class_private_keyword;

        std::ostringstream vtl1_callback_functions {};

        std::ostringstream vtl0_abi_boundary_functions {};
        vtl0_abi_boundary_functions << c_vtl0_abi_boundary_functions_comment;

        std::ostringstream vtl0_abi_impl_callback_functions {};
        vtl0_abi_impl_callback_functions << c_vtl0_abi_impl_callback_functions_comment;

        std::ostringstream vtl0_developer_declaration_functions {};
        vtl0_developer_declaration_functions << c_vtl0_developer_declaration_functions_comment;

        std::ostringstream vtl1_side_of_vtl0_callback_functions {};
        vtl1_side_of_vtl0_callback_functions << c_vtl1_side_of_vtl0_developer_callback_functions_comment;

        // Add allocate vtl0 memory function from ABI base file.
        std::ostringstream vtl0_class_method_addresses;
        auto parameter_separator = (number_of_functions == 0) ? "" : ",";;
        auto addresses_separator = "";
        vtl0_class_method_addresses << c_allocate_memory_callback_to_address.data();
        vtl0_class_method_addresses << c_deallocate_memory_callback_to_address.data();
        std::ostringstream vtl0_class_method_names;
        vtl0_class_method_names << c_allocate_memory_callback_to_name.data();
        vtl0_class_method_names << c_deallocate_memory_callback_to_name.data();

        // Start index at 3 (1 indexed) since we already added both our abi allocate and
        // deallocate memory callbacks. A function index will be used as a key and the
        // function address as the value in a map stored in vtl1. 
        auto vtl1_map_function_index = c_number_of_abi_callbacks + 1;
        auto current_iteration = 0U;
        for (auto& function : functions)
        {
            auto param_info = GetInformationAboutParameters(function, developer_types);

            auto generated_callback_in_namespace = std::format(
               c_generated_callback_in_namespace,
               generated_namespace,
               generated_class_name,
               function.abi_m_name);

            auto vtl1_call_to_vtl0_callback = std::format(
                c_vtl1_call_to_vtl0_callback,
                generated_callback_in_namespace);

            // This is the vtl1 static function that the developer will call into from vtl1 with the
            // same parameters as their vtl0 callabck function. This initiates the abi call from vtl1 
            // to the vtl0 abi boundary function for this specific function.
            vtl1_side_of_vtl0_callback_functions << BuildInitialCallerFunction(
                function,
                vtl1_call_to_vtl0_callback,
                true,
                developer_types,
                param_info);

            auto vtl0_call_to_vtl0_callback = std::format(
                c_vtl0_call_to_vtl0_callback,
                function.abi_m_name,
                function.abi_m_name);

            // This is the vtl0 callback that will call into our abi vtl0 callback implementation.
            // This callback is what vtl1 will call with CallEnclave.
            vtl0_abi_boundary_functions << BuildTrustBoundaryFunction(
                function,
                vtl0_call_to_vtl0_callback,
                true,
                param_info);
                
            // This is our vtl0 abi callback implementation that will finally pass the parameters
            // to the developers vtl0 impl function.
            vtl0_abi_impl_callback_functions << BuildAbiImplFunction(
                function,
                function.m_name,
                param_info);

            // This is the developers vtl0 impl function. The develper will implement this static class
            // method.
            vtl0_developer_declaration_functions << std::format(
                c_static_declaration,
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

            current_iteration++;
            parameter_separator = (current_iteration + 1U == number_of_functions) ? "" : ",";
        }

        // This is the array of callbacks addresses that will be passed to vtl1 with the abi's register
        // callbacks functions, that we export from the enclave dll.
        auto vtl0_class_callbacks_member = std::format(
            c_vtl0_class_add_callback_member,
            number_of_functions_plus_allocators,
            vtl0_class_method_addresses.str(),
            number_of_functions_plus_allocators,
            vtl0_class_method_names.str());
        
        vtl0_class_private_portion 
            << vtl0_abi_boundary_functions.str()
            << vtl0_abi_impl_callback_functions.str()
            << vtl0_class_callbacks_member;

        // Additional processing will be done to complete the class.
        // But for now we'll combine the public and private class info into one.
        vtl0_class_public_functions << vtl0_developer_declaration_functions.str();

        return EnclaveToHostContent {
            std::move(vtl0_class_public_functions),
            std::move(vtl0_class_private_portion),
            std::move(vtl1_side_of_vtl0_callback_functions)
        };
    }

    std::string CppCodeBuilder::CombineAndBuildHostAppEnclaveClass(
        std::string_view generated_class_name,
        std::string_view generated_namespace_name,
        const std::ostringstream& vtl0_class_public_content,
        const std::ostringstream& vtl0_class_private_content)
    {
        auto vtl0_class_name = generated_class_name;
        auto [vtl0_class_header, vtl0_class_body, vtl0_class_footer] = BuildStartOfDefinition(
            EDL_STRUCT_KEYWORD,
            vtl0_class_name);
        
        auto full_class = std::format(
            c_vtl0_class_structure,
            vtl0_class_header.str(),
            vtl0_class_body.str(),
            std::format(c_vtl0_class_constructor, vtl0_class_name),
            vtl0_class_public_content.str(),
            vtl0_class_private_content.str(),
            vtl0_class_footer.str());

        auto vtl0_class_in_namespace = std::format(
            c_vtl0_class_hostapp_namespace,
            generated_namespace_name, 
            full_class);

        return std::format(
            "{}{}{}", 
            c_autogen_header_string, 
            c_vtl0_class_start_of_file,
            vtl0_class_in_namespace);
    }

    std::string CppCodeBuilder::CombineAndBuildVtl1ImplementationsHeader(
        std::string_view generated_namespace_name,
        const std::ostringstream& vtl1_developer_declarations,
        const std::ostringstream& vtl1_callback_impl_functions,
        const std::ostringstream& vtl1_abi_impl_functions)
    {
        auto vtl1_impls_in_namespace = std::format(
            c_vtl1_enclave_func_impl_namespace, 
            generated_namespace_name,
            vtl1_developer_declarations.str(),
            vtl1_callback_impl_functions.str(),
            vtl1_abi_impl_functions.str());

        return std::format("{}{}{}",
            c_autogen_header_string, 
            c_vtl1_enclave_func_impl_start_of_file,
            vtl1_impls_in_namespace);
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
            generated_namespace_name,
            pragma_link_statements.str(),
            exported_definitions.str());
    }

    std::string CppCodeBuilder::BuildVtl1BoundaryFunctionsStubHeader(
        std::string_view generated_namespace_name,
        std::span<Function> functions)
    {
        std::ostringstream stub_declarations {};

        for (auto& function : functions)
        {
            auto generated_func_name = std::format(c_generated_stub_name_no_quotes, function.abi_m_name);
            stub_declarations << std::format(c_abi_boundary_func_declaration_for_stubs, generated_func_name);
        }
        
        auto register_abi_declaration = std::format(
            c_vtl1_register_callbacks_abi_export_name,
            generated_namespace_name);

        stub_declarations << std::format(c_abi_boundary_func_declaration_for_stubs, register_abi_declaration);

        return std::format(
            c_vtl1_export_stub_declarations_header,
            c_autogen_header_string,
            generated_namespace_name, 
            stub_declarations.str());
    }
}
