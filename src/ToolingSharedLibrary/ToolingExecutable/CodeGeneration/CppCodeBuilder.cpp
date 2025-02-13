// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once 
#include <pch.h>
#include <Edl\Structures.h>
#include <Edl\Utils.h>
#include <CodeGeneration\Contants.h>
#include <CodeGeneration\CodeGeneration.h>
#include <sstream>
using namespace EdlProcessor;

namespace CodeGeneration
{
    std::string CppCodeBuilder::BuildDeveloperTypesHeader(
        const std::unordered_map<std::string, std::shared_ptr<DeveloperType>>& developer_types)
    {
        std::ostringstream types_header {};

        for (auto&& [name, type] : developer_types)
        {
            types_header << BuildDeveloperType(*type);
        }

        auto start_of_file = std::format(c_developer_types_start_of_file, c_autogen_header_string);
        start_of_file = std::format(c_developer_types_start_of_file, c_autogen_header_string);
        auto body = std::format(c_developer_types_namespace, types_header.str());

        return std::format("{}{}\n", start_of_file, body);
    }

    CppCodeBuilder::Definition CppCodeBuilder::BuildStartOfDefinition(
        std::string_view type_name,
        std::string_view identifier_name)
    {
        CppCodeBuilder::Definition definition{};

        if (identifier_name.empty())
        {
            definition.m_header << std::format("{}\n", type_name);
        }
        else
        {
            definition.m_header << std::format("{} {}\n", type_name, identifier_name);
        }

        definition.m_body << std::format("{}\n", LEFT_CURLY_BRACKET);
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

    std::string CppCodeBuilder::GetTypeInfoForFunction(
        const Declaration& declaration,
        ParamModifier modifier)
    {
        std::string type = GetSimpleTypeInfo(declaration.m_edl_type_info);;

        if (!declaration.m_array_dimensions.empty())
        {
            auto type_info = GetSimpleTypeInfo(declaration.m_edl_type_info);
            type = BuildStdArrayType(type_info, declaration.m_array_dimensions);
        }        

        std::string pointer = (declaration.HasPointer()) ? "*" : "";
        bool should_add_reference = (modifier == ParamModifier::Reference || modifier == ParamModifier::ConstReference);
        std::string punctuator = (should_add_reference && pointer.empty()) ? "&" : pointer;

        if (declaration.m_attribute_info)
        {
            ParsedAttributeInfo attribute = declaration.m_attribute_info.value();
            if (attribute.m_in_present && attribute.m_out_present)
            {
                return std::format("{}{}", type, punctuator);
            }
            else if (attribute.m_out_present && !declaration.HasPointer())
            {
                return std::format("{}{}", type, punctuator);
            }
            else if (attribute.m_out_present && declaration.HasPointer())
            {
                // TODO: Update to use smart pointers so abi controls lifetime.
                return std::format("{}{}{}", type, ASTERISK, ASTERISK);
            }
        }

        if (modifier == ParamModifier::ConstReference || modifier == ParamModifier::ConstOnly)
        {
            return std::format("const {}{}", type, punctuator);
        }

        return std::format("{}{}", type, punctuator);
    }

    std::string CppCodeBuilder::GetSimpleTypeInfo(const EdlTypeInfo& info)
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
                return std::format("std::{}", info.m_name);
            case EdlTypeKind::String:
                return c_enclave_string_type.data();
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

        std::string array_string = BuildStdArrayType(type, dimensions, index + 1U);
        return std::format("{}{}, {}>", c_array_initializer, array_string, dimensions[index]);
    }

    std::string CppCodeBuilder::BuildArrayType(const Declaration& declaration)
    {
        if (declaration.m_parent_kind == DeclarationParentKind::Function)
        {
            std::string type = GetTypeInfoForFunction(declaration, ParamModifier::ConstReference);
            return std::format("{} {}", type, declaration.m_name);
        }

        auto type_info = GetSimpleTypeInfo(declaration.m_edl_type_info);
        auto array_info = BuildStdArrayType(type_info, declaration.m_array_dimensions);
        return std::format("{} {}", array_info, declaration.m_name);
    }

    std::string CppCodeBuilder::BuildNonArrayType(const Declaration& declaration)
    {
        if (declaration.m_parent_kind == DeclarationParentKind::Function)
        {
            std::string type = GetTypeInfoForFunction(declaration, ParamModifier::ConstReference);
            return std::format("{} {}", type, declaration.m_name);
        }

        auto pointer = declaration.HasPointer() ? "*" : "";
        return std::format("{}{} {}", GetSimpleTypeInfo(declaration.m_edl_type_info), pointer, declaration.m_name);
    }

    std::string CppCodeBuilder::BuildStructFieldOrFunctionParameter(const Declaration& declaration)
    {
        if (!declaration.m_array_dimensions.empty())
        {
            return BuildArrayType(declaration);
        }

        return BuildNonArrayType(declaration);
    }

    std::string CppCodeBuilder::BuildStructDefinition(const DeveloperType& developer_types)
    {
        auto [struct_header, struct_body, struct_footer] = BuildStartOfDefinition(
            EDL_STRUCT_KEYWORD,
            developer_types.m_name);

        for (auto& field : developer_types.m_fields)
        {
            struct_body << std::format(
                "{}{}{}\n",
                c_four_spaces,
                BuildStructFieldOrFunctionParameter(field),
                SEMI_COLON);
        }

        return std::format("\n{}\n{}{}{}{}\n",
            c_pragma_pack,
            struct_header.str(),
            struct_body.str(),
            struct_footer.str(),
            c_pragma_pop);
    }

    std::string CppCodeBuilder::BuildDeveloperType(const DeveloperType& type)
    {
        if (type.m_type_kind == EdlTypeKind::Enum || type.m_type_kind == EdlTypeKind::AnonymousEnum)
        {
            return BuildEnumDefinition(type);
        }
        else
        {
            return BuildStructDefinition(type);
        }
    }

    std::string  CppCodeBuilder::BuildFunctionParameters(
        const Function& function,
        CodeGenFunctionKind function_kind,
        const FunctionParameterInfo& param_info)
    {
        std::ostringstream function_parameters;
        function_parameters << "(";
        
        for (auto i = 0U; i < function.m_parameters.size(); i++)
        {
            Declaration declaration = function.m_parameters[i];
            auto parameter = BuildStructFieldOrFunctionParameter(declaration);
            auto complete_parameter = AddSalToParameter(declaration, parameter);

            if (i + 1U < function.m_parameters.size())
            {
                function_parameters << std::format("{}{} ", complete_parameter, COMMA);
            }
            else
            {
                function_parameters << std::format("{}", complete_parameter);
            }
        }

        if (function_kind == CodeGenFunctionKind::Abi && param_info.m_are_return_params_needed)
        {
            auto param_container = std::format(
                c_parameter_container_type,
                param_info.m_types_to_return_in_tuple.str());

            auto separator = (function.m_parameters.empty()) ? "" : ", ";
            function_parameters << std::format(c_abi_return_param_declaration, separator, param_container);
        }
        
        function_parameters << ")";

        return function_parameters.str();
    }

    void CppCodeBuilder::SetupCopyOfReturnParameterStatements(
        const Declaration& parameter,
        const std::uint32_t index,
        FunctionParameterInfo& param_info,
        FunctionDirection direction)
    {
        auto& attribute = parameter.m_attribute_info.value();
        std::string tuple_into_parameter {};
        std::string parameter_into_tuple{};
        auto get_tuple_value = std::format(c_std_get_tuple_value, index);
        bool has_pointer = parameter.HasPointer();
        auto param_type = GetSimpleTypeInfo(parameter.m_edl_type_info);

        if (direction == FunctionDirection::HostAppToEnclave)
        {
            // Copy the returned tuple value into the developers actual parameter.           
            tuple_into_parameter = GetCopyStatement(
                has_pointer,
                attribute,
                param_type,
                parameter.m_name,
                get_tuple_value,
                ParamCopyDirection::ForReturnCase_InsideVtl0CopyVtl0HeapParamToVariable);

            // Copy actual parameter that was passed into the developers impl function into the
            // return tuple value.
            parameter_into_tuple = GetCopyStatement(
                has_pointer,
                attribute,
                param_type,
                get_tuple_value,
                parameter.m_name,
                ParamCopyDirection::ForReturnCase_InsideVtl1CopyVtl1ParamToVtl0Heap);
        }
        else
        {
            // Copy the returned tuple value into the developers actual parameter.           
            tuple_into_parameter = GetCopyStatement(
                has_pointer,
                attribute,
                param_type,
                parameter.m_name,
                get_tuple_value,
                ParamCopyDirection::ForReturnCase_InsideVtl1CopyVtl0HeapParamToVariable);

            // Copy actual parameter that was passed into the developers impl function into the
            // return tuple value.
            parameter_into_tuple = GetCopyStatement(
                has_pointer,
                attribute,
                param_type,
                get_tuple_value,
                parameter.m_name,
                ParamCopyDirection::ForReturnCase_InsideVtl0CopyVtl0ParamToVtl0Heap);
        }

        param_info.m_copy_tuple_values_into_parameters << tuple_into_parameter;
        param_info.m_copy_parameters_into_tuple_values << parameter_into_tuple;
    }

    void CppCodeBuilder::SetupCopyOfForwardedParameterStatements(
        const Declaration& parameter,
        const std::uint32_t index,
        FunctionParameterInfo& param_info,
        FunctionDirection direction)
    {
        auto& attribute = parameter.m_attribute_info.value();
        std::string parameter_into_tuple {};
        auto get_tuple_value = std::format(c_std_get_vtl1_input_tuple_value, index);
        bool has_pointer = parameter.HasPointer();
        auto param_type = GetSimpleTypeInfo(parameter.m_edl_type_info);

        // VTL0 can't read vtl1 memory, so build a copy statement to copy all parameters
        // that need to be forwarded from vtl1 to vtl0.
        if (has_pointer && direction == FunctionDirection::EnclaveToHostApp)
        {
            // Copy the input param value into the vtl0 heap version.           
            parameter_into_tuple = GetCopyStatement(
                has_pointer,
                attribute,
                param_type,
                get_tuple_value,
                parameter.m_name,
                ParamCopyDirection::ForForwardingCase_InsideVtl1CopyVtl1ParamToVtl0Heap);

            param_info.m_copy_vtl1_parameters_into_vtl0_heap_tuple << parameter_into_tuple;
        }
    }

    CppCodeBuilder::FunctionParameterInfo CppCodeBuilder::GetParametersAndTupleInformation(
        const Function& function,
        FunctionDirection direction)
    {
        FunctionParameterInfo param_info {};
        std::string in_out_separator {};
        auto in_out_parm_index = 0U;

        // We copy enclave parameters inside a tuple so we can forward them to an abi function or
        // to the developers impl function. To do this we need to capture the types for
        // the parameters to forward, their names, and the types of parameters that need
        // to be returned e.g function return values, Out and InOut values. Indexes are used to index
        // the correct tuple value in relation to a forwarded parameter or In/Out/return value.
        for (auto params_index = 0U; params_index < function.m_parameters.size(); params_index++)
        {
            auto list_ender = (params_index + 1U < function.m_parameters.size()) ? "," : "";
            Declaration param = function.m_parameters[params_index];
            std::string type_info = GetTypeInfoForFunction(param, ParamModifier::ConstOnly);
            param_info.m_names_list << std::format("{}{}", param.m_name, list_ender);

            // For vtl1 to vtl0 parameter passing we need to copy parameters to a vtl0 tuple
            // and forward that to vtl0. [In] parameters will have a const value so we need
            // to remove the const so we can copy them without the const part.
            if (param.HasPointer() && !param.IsInOutOrOutParameter() && direction == FunctionDirection::EnclaveToHostApp)
            {
                std::string type_info_no_const = GetTypeInfoForFunction(param, ParamModifier::NoConstNoReference);
                param_info.m_types_list << std::format("(const_cast<{}>({})){}", type_info_no_const, param.m_name, list_ender);
                param_info.m_types_in_tuple << std::format("{}{}", type_info_no_const, list_ender);
            }
            else
            {
                // We copy by value for in parameters or parameters without pointers. For HostApp to enclave calls 
                // we do not need to copy the parameters to an intermediary object, we can forward them vtl1 as is
                // who can then copy them into vtl1 memory.
                param_info.m_types_in_tuple << std::format("{}{}", type_info, list_ender);
                param_info.m_types_list << std::format("{}{}", param.m_name, list_ender);
            }

            // Pointer parameters need to be copied if from vtl1 memory into vtl0 memory before passing them
            // through abi to vtl0.
            if (param.HasPointer() && direction == FunctionDirection::EnclaveToHostApp)
            {
                SetupCopyOfForwardedParameterStatements(param, params_index, param_info, direction);
            }

            // Build the statements to copy the updated InOut/Out/return values to the abi functions return
            // object.
            if (param.IsInOutOrOutParameter())
            {
                SetupCopyOfReturnParameterStatements(param, in_out_parm_index, param_info, direction);
                in_out_separator = (in_out_parm_index == 0) ? "" : ",";
                param_info.m_types_to_return_in_tuple << std::format("{}{}", in_out_separator, type_info);
                param_info.m_names_to_return_in_tuple << std::format("{}{}", in_out_separator, param.m_name);

                in_out_parm_index++;
            }
        }

        auto pointer = (function.m_return_info.is_pointer) ? "*" : "";
        param_info.m_function_return_value = std::format("{}{}", GetSimpleTypeInfo(function.m_return_info), pointer);

        bool is_void_function = function.m_return_info.m_type_kind == EdlTypeKind::Void;
        param_info.m_are_return_params_needed = (!is_void_function || (in_out_parm_index > 0));
        param_info.m_function_return_type_void = is_void_function;

        // Finally add return value as the last function return parameter
        in_out_separator = (in_out_parm_index == 0) ? "" : ",";

        if (!is_void_function)
        {
            param_info.m_types_to_return_in_tuple << std::format(
                "{}{}",
                in_out_separator,
                param_info.m_function_return_value);

            param_info.m_names_to_return_in_tuple <<
                std::format("{}{}", 
                in_out_separator,
                c_return_variable_name);
        }
        
        return param_info;
    }

    static inline std::string GetFunctionNameForAbi(std::string_view original_name)
    {
        // Since we allow developer functions to contain the same name but with different
        // parameters, we need to make sure the non developer facing functions are unique
        // in our abi layer. So we append a number to the function name.
        static std::uint32_t abi_function_index {};

        return std::format("{}{}", original_name, abi_function_index++);
    }

    std::string CppCodeBuilder::BuildInitialCallerFunction(
        const Function& function,
        std::string_view abi_function_to_call,
        const FunctionParameterInfo& param_info,
        FunctionDirection direction,
        bool should_be_static)
    {
        auto static_keyword = should_be_static ? c_static_keyword.data() : "";
        auto function_declaration = std::format(
            "{}{} {}{}",
            static_keyword,
            param_info.m_function_return_value,
            function.m_name,
            BuildFunctionParameters(function, CodeGenFunctionKind::Developer, param_info));

        std::string parameters_using_statement = std::format(
            c_parameter_container,
            param_info.m_types_in_tuple.str(),
            param_info.m_types_list.str());

        std::string return_parameters_using_statement = std::format(
            c_parameter_container_type,
            param_info.m_types_to_return_in_tuple.str());

        std::string vtl1_input_params_copied_to_vtl0{};
        if (direction == FunctionDirection::EnclaveToHostApp)
        {
            // copy vtl1 input params to vtl0 buffer. Developer must free.
            vtl1_input_params_copied_to_vtl0 = std::format(
                c_vtl1_copy_input_params_to_vtl0_buffer,
                param_info.m_copy_vtl1_parameters_into_vtl0_heap_tuple.str());
        }

        auto return_statement = c_empty_return;
        std::string final_part_of_function {};

        if (!param_info.m_function_return_type_void)
        {
            return_statement = c_return_value_to_initial_caller;
        }

        if (param_info.m_are_return_params_needed)
        {
            final_part_of_function = std::format(
                c_setup_return_params_tuple,
                param_info.m_copy_tuple_values_into_parameters.str(),
                return_statement);
        }

        return std::format(
            c_initial_caller_function_body,
            function_declaration,
            parameters_using_statement,
            return_parameters_using_statement,
            vtl1_input_params_copied_to_vtl0,
            abi_function_to_call,
            final_part_of_function);
    }

    std::string CppCodeBuilder::BuildAbiBoundaryFunction(
        const Function& function,
        std::string_view boundary_function_name,
        std::string_view abi_function_to_call,
        bool is_vtl0_callback,
        const FunctionParameterInfo& param_info)
    {
        std::string params_using_statement = std::format(
            c_parameter_container_type,
            param_info.m_types_in_tuple.str());

        std::string return_params_using_statement = std::format(
            c_parameter_container_type,
            param_info.m_types_to_return_in_tuple.str());

        std::string inner_body = std::format(
            c_inner_abi_function,
            params_using_statement,
            return_params_using_statement,
            abi_function_to_call);

        auto return_statement = (is_vtl0_callback) ? c_static_void_ptr : c_void_ptr;

        return std::format(
            c_outer_abi_function,
            return_statement,
            boundary_function_name,
            inner_body);
    }

    std::string CppCodeBuilder::BuildAbiImplFunction(
        const Function& function,
        std::string_view abi_function_name,
        std::string_view call_impl_str,
        const FunctionParameterInfo& param_info)
    {
        auto abi_parameters = BuildFunctionParameters(function, CodeGenFunctionKind::Abi, param_info);
        std::string call_developer_impl_declaration {};

        std::ostringstream copy_in_out_param_statements {};

        if (param_info.m_are_return_params_needed)
        {
            copy_in_out_param_statements << std::format(
                c_copy_parameters_into_tuple,
                param_info.m_types_to_return_in_tuple.str(),
                param_info.m_names_to_return_in_tuple.str(),
                param_info.m_copy_parameters_into_tuple_values.str());
        }

        if (param_info.m_function_return_type_void)
        {
            call_developer_impl_declaration = std::format(
                c_abi_func_return_null_when_void,
                call_impl_str,
                param_info.m_names_list.str(),
               copy_in_out_param_statements.str());
        }
        else
        {
            call_developer_impl_declaration = std::format(
                c_abi_func_return_value,
                call_impl_str,
                param_info.m_names_list.str(),
               copy_in_out_param_statements.str());
        }

        return std::format(
            c_generated_abi_impl_function,
            abi_function_name,
            abi_parameters,
            call_developer_impl_declaration);
    }

    std::string CppCodeBuilder::BuildEnclaveModuleDefinitionFile(std::string_view exported_functions)
    {
        auto module_def = std::format(c_enclave_def_file_content, c_autogen_header_string, exported_functions);

        // Replace the // in the autogen header. This way we can have a single source for the header
        // instead of duplicating it.
        size_t pos = module_def.find("//");
        while (pos != std::string::npos)
        {
            module_def.replace(pos, 2, ";");
            pos = module_def.find("//", pos + 1U);
        }

        return module_def;
    }

    CppCodeBuilder::HostToEnclaveContent CppCodeBuilder::BuildHostToEnclaveFunctions(
        std::string_view generated_namespace,
        std::unordered_map<std::string, Function>& functions)
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

        for (auto&& [name, function] : functions)
        {
            auto param_info = GetParametersAndTupleInformation(function, FunctionDirection::HostAppToEnclave);
            auto abi_function_name = GetFunctionNameForAbi(function.m_name);
            auto vtl1_exported_func_name = std::format(c_generated_stub_name, abi_function_name);
            auto vtl0_call_to_vtl1_export = std::format(
                c_vtl0_call_to_vtl1_export,
                vtl1_exported_func_name);

            // This is the vtl0 abi function that the developer will call into to start the flow
            // of calling their vtl1 enclave function impl.
            vtl0_side_of_vtl1_developer_impl_functions << BuildInitialCallerFunction(
                function,
                vtl0_call_to_vtl1_export,
                param_info,
                FunctionDirection::HostAppToEnclave,
                false);

            auto vtl1_call_to_vtl1_export = std::format(
                c_vtl1_call_to_vtl1_export,
                abi_function_name,
                abi_function_name);

            // This is the vtl0 function that is exported by the enclave and called via a
            // CallEnclave call by the abi.
            vtl1_abi_boundary_functions << BuildAbiBoundaryFunction(
                function,
                abi_function_name,
                vtl1_call_to_vtl1_export,
                false,
                param_info);

            auto call_developer_impl_str = std::format(c_vtl1_call_developer_impl, function.m_name);

            // This is the vtl1 abi function that will call the developers vtl1 function implementation.
            std::string vtl1_abi_impl_definition = BuildAbiImplFunction(
                    function,
                    abi_function_name,
                    call_developer_impl_str,
                    param_info);

                // VTL1 enclave function that the developer will implement. It is called by the vtl1
                // abi function impl for this particular function.
            vtl1_developer_declaration_functions << std::format(
                c_function_declaration,
                param_info.m_function_return_value,
                function.m_name,
                BuildFunctionParameters(function, CodeGenFunctionKind::Developer, param_info));
            
            vtl1_abi_impl_functions << vtl1_abi_impl_definition;

            vtl1_generated_module_exports << std::format(c_exported_function_in_module, abi_function_name);
        }

        vtl0_class_public_portion << vtl0_side_of_vtl1_developer_impl_functions.str();

        // Add register callbacks abi export to module file and add it at the end of the vtl1 stubs file.
        vtl1_generated_module_exports << c_vtl1_register_callbacks_abi_export_name;
        vtl1_abi_boundary_functions << c_vtl1_register_callbacks_abi_export;

        auto vtl1_stubs_in_namespace =
            std::format(c_vtl1_enclave_stub_namespace, generated_namespace, vtl1_abi_boundary_functions.str());

        return HostToEnclaveContent {
            std::move(vtl0_class_public_portion),
            std::format("{}{}{}",c_autogen_header_string, c_vtl1_enclave_stub_includes, vtl1_stubs_in_namespace),
            std::move(vtl1_developer_declaration_functions),
            std::move(vtl1_abi_impl_functions),
            BuildEnclaveModuleDefinitionFile(vtl1_generated_module_exports.str())
        };
    }

    CppCodeBuilder::EnclaveToHostContent CppCodeBuilder::BuildEnclaveToHostFunctions(
        std::unordered_map<std::string, Function>& functions)
    {
        size_t number_of_functions = functions.size();
        size_t number_of_functions_plus_allocators = functions.size() + c_number_of_abi_callbacks;
        std::ostringstream vtl0_class_public_functions {};
        std::ostringstream vtl0_class_private_portion {};
        vtl0_class_public_functions << c_vtl0_enclave_class_public_keyword;
        vtl0_class_private_portion << c_vtl0_enclave_class_private_keyword;

        std::ostringstream vtl1_callback_functions {};

        std::ostringstream vtl0_abi_boundary_functions{};
        vtl0_abi_boundary_functions << c_vtl0_abi_boundary_functions_comment;

        std::ostringstream vtl0_abi_impl_callback_functions{};
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


        // Start index at 3 (1 indexed) since we already added both our abi allocate and
        // deallocate memory callbacks. A function index will be used as a key and the
        // function address as the value in a map stored in vtl1. 
        auto vtl1_map_function_index = c_number_of_abi_callbacks + 1;
        auto current_iteration = 0U;
        for (auto&& [name, function] : functions)
        {
            // Update name so there are no conflicts if the same name is used for a trusted function.
            function.m_name = std::format(c_untrusted_function_name, function.m_name);
            auto abi_function_name = GetFunctionNameForAbi(function.m_name);
            auto param_info = GetParametersAndTupleInformation(function, FunctionDirection::EnclaveToHostApp);

            auto vtl1_call_to_vtl0_callback = std::format(
                c_vtl1_call_to_vtl0_callback,
                vtl1_map_function_index++);

            // This is the vtl1 static function that the developer will call into from vtl1 with the
            // same parameters as their vtl0 impl function. This initiates the abi call from vtl1 
            // to the vtl0 abi boundary function for this specific function.
            vtl1_side_of_vtl0_callback_functions << BuildInitialCallerFunction(
                function,
                vtl1_call_to_vtl0_callback,
                param_info,
                FunctionDirection::EnclaveToHostApp,
                true);

            auto vtl0_call_to_vtl0_callback = std::format(
                c_vtl0_call_to_vtl0_callback,
                abi_function_name,
                abi_function_name);

            // This is the vtl0 callback that will call into our abi vtl0 callback implementation.
            // This callback is what vtl1 will call with CallEnclave.
            vtl0_abi_boundary_functions << BuildAbiBoundaryFunction(
                function,
                abi_function_name,
                vtl0_call_to_vtl0_callback,
                true,
                param_info);

            // This is our vtl0 abi callback implementation that will finally pass the parameters
            // to the developers vtl0 impl function.
            vtl0_abi_impl_callback_functions << BuildAbiImplFunction(
                function,
                abi_function_name,
                function.m_name,
                param_info);

            // This is the developers vtl0 impl functionn. The develper will implement this static class
            // method.
            vtl0_developer_declaration_functions << std::format(
                c_static_declaration,
                param_info.m_function_return_value,
                function.m_name,
                BuildFunctionParameters(function, CodeGenFunctionKind::Developer, param_info));         

            // capture the addresses for each developer callback so we can pass them to vtl1 later.
            vtl0_class_method_addresses << std::format(
                c_callback_to_address, 
                abi_function_name,
                parameter_separator);

            current_iteration++;
            parameter_separator = (current_iteration + 1U == number_of_functions) ? "" : ",";
        }

        // This is the array of callbacks addresses that will be passed to vtl1 with the abi's register
        // callbacks functions, that we export from the enclave dll.
        auto vtl0_class_callbacks_member = std::format(
            c_vtl0_class_add_callback_member,
            number_of_functions_plus_allocators,
            vtl0_class_method_addresses.str());
        
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

        auto full_class = std::format("{}{}{}{}{}{}",
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
}
