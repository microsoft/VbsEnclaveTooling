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
using namespace CodeGeneration::CppCodeBuilder;
using namespace EdlProcessor;
using namespace CodeGeneration::Flatbuffers;

namespace CodeGeneration
{
    std::ostringstream CppCodeBuilder::CreateDeveloperTypeStructs(
        const std::vector<std::shared_ptr<DeveloperType>>& developer_types_insertion_list)
    {
        std::ostringstream types_header {};
        std::ostringstream enums_definitions {};
        std::ostringstream struct_declarations {};

        for (auto& type : developer_types_insertion_list)
        {
            if (type->IsEdlType(EdlTypeKind::Enum) || type->IsEdlType(EdlTypeKind::AnonymousEnum))
            {
                enums_definitions << BuildEnumDefinition(*type);
            }
            else
            {
                struct_declarations << std::format(c_using_statements_for_developer_struct, type->m_name, type->m_name);
            }
        }

        types_header << struct_declarations.str();
        types_header << enums_definitions.str();
        types_header << c_flatbuffers_helper_functions;

        for (auto& type : developer_types_insertion_list)
        {
            if (type->IsEdlType(EdlTypeKind::Struct))
            {
                types_header << BuildStructDefinitionForDeveloperType(type->m_name, type->m_fields);
            }
        }

        return types_header;
    }

    std::string CppCodeBuilder::BuildTypesHeader(const std::ostringstream& types)
    {
        auto start_of_file = std::format(c_developer_types_start_of_file, c_autogen_header_string);
        auto body = std::format(c_developer_types_namespace, types.str());

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
                // m_value, if it exists is the numeric value the developer used on the right hand side of the 
                // enum value definition. E.g FirstEnum = 4. In this case m_value will be the number 4. 
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
        ParameterModifier modifier = ParameterModifier::NoConst)
    {
        std::string type = GetSimpleTypeInfo(declaration.m_edl_type_info);

        if (!declaration.m_array_dimensions.empty())
        {
            auto type_info = GetSimpleTypeInfo(declaration.m_edl_type_info);
            type = BuildStdArrayType(type_info, declaration.m_array_dimensions);
        }

        if (declaration.m_attribute_info)
        {
            ParsedAttributeInfo attribute = declaration.m_attribute_info.value();
            if ((attribute.m_in_and_out_present || attribute.m_out_present) && !declaration.HasPointer())
            {
                return std::format("{}&", type);
            }
            else if (attribute.m_in_and_out_present && declaration.HasPointer())
            {
                return std::format("{}*", type);
            }
            else if (attribute.m_out_present && declaration.HasPointer())
            {
                return std::format("{}**", type);
            }
        }

        auto const_str = (modifier == ParameterModifier::InParameterConst) ? "const " : "";

        // just an in param but developer did not specify attributes e.g by default we implicitly will see these
        // as in parameters. Or the developer did specify an attribut but it was an in param.
        if (declaration.HasPointer())
        {
            return std::format("{}{}*", const_str, type);
        }

        if (!declaration.HasPointer() && const_ref_types.contains(declaration.m_edl_type_info.m_type_kind))
        {
            return std::format("{}{}&", const_str, type);
        }

        return std::format("{}{}", const_str, type);
    }

    std::string CppCodeBuilder::GetTypeInfoForFunctionParameter(const Declaration& declaration)
    {
        std::string type = GetFullDeclarationType(declaration);

        if (declaration.IsInParameterOnly())
        {
            return std::format("const {}&", type);
        }

        return std::format("{}&", type);
    }

    std::string CppCodeBuilder::GetSimpleTypeInfoWithPointerInfo(const EdlTypeInfo& info)
    {
        std::string pointer = info.is_pointer ? "*" : "";
        return GetSimpleTypeInfo(info) + pointer;
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

    std::string CppCodeBuilder::BuildArrayType(
        const Declaration& declaration)
    {
        auto type_info = GetSimpleTypeInfo(declaration.m_edl_type_info);
        auto array_info = BuildStdArrayType(type_info, declaration.m_array_dimensions);
        return std::format("{} {}", array_info, declaration.m_name);
    }

    std::string CppCodeBuilder::BuildStructField(
        const Declaration& declaration)
    {
        return std::format("{} {}", GetFullDeclarationType(declaration), declaration.m_name);
    }

    std::string GetConverterFunctionForDeveloperStruct(
        std::string_view struct_name,
        const std::vector<Declaration>& fields)
    {
        std::ostringstream struct_body {};
        auto flatbuffer_type = std::format(c_flatbuffer_native_table_type_suffix, struct_name);

        // Add flatbuffer to developer type static function
        std::string flatbuffer_to_dev_type_func_body = BuildConversionFunctionBody(
            fields,
            FlatbufferConversionKind::ToDevType);

        struct_body << std::format(
            c_convert_to_dev_type_function_definition_reference,
            struct_name,
            flatbuffer_type,
            struct_name,
            flatbuffer_to_dev_type_func_body);

        struct_body << std::format(
            c_convert_to_dev_type_function_definition_unique_ptr,
            struct_name,
            flatbuffer_type,
            struct_name);

        struct_body << std::format(
            c_convert_to_dev_type_function_definition_no_ptr,
            struct_name,
            flatbuffer_type,
            struct_name,
            flatbuffer_to_dev_type_func_body);

        struct_body << std::format(
            c_convert_to_dev_type_function_definition_no_ptr2,
            struct_name,
            flatbuffer_type,
            struct_name);

        // Add developer to flatbuffer static function
        std::string dev_type_to_flatbuffer_func_body = BuildConversionFunctionBody(
            fields,
            FlatbufferConversionKind::ToFlatbuffer);

        struct_body << std::format(
            c_convert_to_flatbuffer_function_definition_reference,
            flatbuffer_type,
            struct_name,
            flatbuffer_type,
            dev_type_to_flatbuffer_func_body);

        return struct_body.str();
    }

    std::string CppCodeBuilder::BuildStructDefinitionForDeveloperType(
        std::string_view struct_name,
        const std::vector<Declaration>& fields)
    {
        auto [struct_header, struct_body, struct_footer] = BuildStartOfDefinition(
            EDL_STRUCT_KEYWORD,
            struct_name);

        std::ostringstream to_flatbuffer_inout_function_args {};
        std::ostringstream to_flatbuffer_all_function_args {};
        size_t inout_index = 0U;
        for (auto& field : fields)
        {
            struct_body << std::format(
                "{}{} {{}}{}\n",
                c_four_spaces,
                BuildStructField(field),
                SEMI_COLON);
        }

        struct_body << GetConverterFunctionForDeveloperStruct(struct_name, fields);

        return std::format("\n{}{}{}\n",
            struct_header.str(),
            struct_body.str(),
            struct_footer.str());
    }

    std::string GetConverterFunctionForNonDeveloperAbiStruct(
        std::string_view struct_name,
        const std::vector<Declaration>& fields,
        std::vector<Declaration> to_flatbuffer_in_and_inout_args_list,
        std::string to_flatbuffer_in_and_inout_params)
    {
        std::ostringstream struct_body {};
        auto flatbuffer_type = std::format(c_flatbuffer_native_table_type_suffix, struct_name);

        std::string flatbuffer_to_dev_type_func_body = BuildConversionFunctionBody(
            fields,
            FlatbufferConversionKind::ToDevType,
            FlatbufferStructFieldsModifier::AbiToDevTypeSingleStruct);

        // Add flatbuffer to developer type static function
        struct_body << std::format(
            c_convert_to_dev_type_function_definition_reference,
            struct_name,
            flatbuffer_type,
            struct_name,
            flatbuffer_to_dev_type_func_body);

        struct_body << std::format(
            c_convert_to_dev_type_function_definition_unique_ptr,
            struct_name,
            flatbuffer_type,
            struct_name);

        std::string dev_type_to_flatbuffer_func_body = BuildConversionFunctionBody(
            fields,
            FlatbufferConversionKind::ToFlatbuffer,
            FlatbufferStructFieldsModifier::AbiToFlatbufferSingleStruct);

        // Add developer to flatbuffer static function which takes in a struct that contains the parameters as fields.
        struct_body << std::format(
            c_convert_to_flatbuffer_function_definition_reference,
            flatbuffer_type,
            struct_name,
            flatbuffer_type,
            dev_type_to_flatbuffer_func_body);

        // Add developer to flatbuffer static function overload that takes a unique ptr as input
        struct_body << std::format(
            c_convert_to_flatbuffer_function_definition_unique_ptr,
            flatbuffer_type,
            struct_name,
            struct_name);

        std::string dev_type_to_flatbuffer_func_body_mult_params = BuildConversionFunctionBody(
            to_flatbuffer_in_and_inout_args_list,
            FlatbufferConversionKind::ToFlatbuffer,
            FlatbufferStructFieldsModifier::AbiToFlatbufferMultipleParameters);

        // Add developer to flatbuffer static function which takes in the function parameters directly
        struct_body << std::format(
            c_convert_to_flatbuffer_function_definition_multi_params,
            flatbuffer_type,
            to_flatbuffer_in_and_inout_params,
            flatbuffer_type,
            dev_type_to_flatbuffer_func_body_mult_params);

        return struct_body.str();
    }

    std::string GetToFlatbufferParameterForFunction(const Declaration& declaration)
    {
        std::string full_type = GetFullDeclarationType(declaration);
        std::string qualifier = GetParameterQualifier(declaration);
        std::string param_declarator = GetParameterDeclarator(declaration);

        return std::format("{} {}{} {}", qualifier, full_type, param_declarator, declaration.m_name);
    }   

    std::string CppCodeBuilder::BuildStructDefinitionForFunctionParams(
        std::string_view struct_name,
        const std::vector<Declaration>& parameters,
        const CppCodeBuilder::FunctionParametersInfo& params_info)
    {
        auto [struct_header, struct_body, struct_footer] = BuildStartOfDefinition(
            EDL_STRUCT_KEYWORD,
            struct_name);

        std::ostringstream to_flatbuffer_in_and_inout_function_args {};
        std::vector<Declaration> to_flatbuffer_in_and_inout_args_list {};
        size_t inout_index = 0U;
        for (size_t param_index = 0U; param_index < parameters.size(); param_index++)
        {
            auto& parameter = parameters[param_index];
            struct_body << std::format(
                "{}{} {{}}{}\n",
                c_four_spaces,
                BuildStructField(parameter),
                SEMI_COLON);

            // Now that we've created a field for the parameter we need to create a string variable that
            // we will use to pass to the ToFlatbuffer function.
            auto all_params_separator = param_index > 0 ? "," : "";
            auto inout_params_separator = inout_index > 0 ? "," : "";
            auto param_str = GetParameterForFunction(parameter);

            if (parameter.IsInParameterOnly() || parameter.IsInOutParameter())
            {
                to_flatbuffer_in_and_inout_function_args << std::format("{} {}", inout_params_separator, param_str);
                to_flatbuffer_in_and_inout_args_list.push_back(parameter);
                inout_index++;
            }
        }

        struct_body << GetConverterFunctionForNonDeveloperAbiStruct(
            struct_name,
            parameters, 
            to_flatbuffer_in_and_inout_args_list,
            to_flatbuffer_in_and_inout_function_args.str());
        

        return std::format("\n{}{}{}\n",
            struct_header.str(),
            struct_body.str(),
            struct_footer.str());
    }

    void CppCodeBuilder::SetupCopyOfReturnParameterStatements(
        const Declaration& parameter,
        const size_t index,
        std::string_view parameter_type,
        std::string_view size_to_copy,
        FunctionParametersInfo& param_info,
        CallFlowDirection call_direction)
    {
        std::string tuple_into_parameter {};
        std::string get_tuple_value {};

        if (call_direction == CallFlowDirection::HostAppToEnclave)
        {
            get_tuple_value = std::format(c_std_get_vtl0_input_tuple_value_for_host_to_enclave, index);

            // Copy the returned tuple value into the developers actual vtl0 parameter.           
            tuple_into_parameter = GetCopyStatement(
                parameter,
                parameter_type,
                size_to_copy,
                parameter.m_name,
                get_tuple_value,
                ParamCopyCase::ReturnFromVtl1ToVtl0_CopyVtl1ParametersToVtl0Parameters);
        }
        else if (call_direction == CallFlowDirection::EnclaveToHostApp)
        {
            get_tuple_value = std::format(c_std_get_vtl1_input_tuple_value_for_enclave_to_host, index);

            // Copy the returned tuple value into the developers actual vtl1 parameter.           
            tuple_into_parameter = GetCopyStatement(
                parameter,
                parameter_type,
                size_to_copy,
                parameter.m_name,
                get_tuple_value,
                ParamCopyCase::ReturnFromVtl0ToVtl1_CopyVtl0ParametersIntoVtl1Parameters);
        }

        param_info.m_copy_updated_values_into_original_function_parameters << tuple_into_parameter;
    }

    void CppCodeBuilder::SetupCopyOfForwardParameterStatements(
        const Declaration& parameter,
        const size_t index,
        std::string_view parameter_type,
        std::string_view size_to_copy,
        FunctionParametersInfo& param_info,
        CallFlowDirection call_direction)
    {
        std::string parameter_copied_into_tuple {};
        std::string get_tuple_value {};

        if (call_direction == CallFlowDirection::HostAppToEnclave)
        {
            get_tuple_value = std::format(c_std_get_vtl0_input_tuple_value_for_host_to_enclave, index);

            // Copy the vtl0 input param value into the vtl1 heap version so we can forward it
            // to the vtl1 function.      
            parameter_copied_into_tuple = GetCopyStatement(
                parameter,
                parameter_type,
                size_to_copy,
                get_tuple_value,
                parameter.m_name,
                ParamCopyCase::CallToVtl1FromVtl0_CopyVtl0ParametersIntoVtl1Parameters);

            param_info.m_copy_vtl0_parameters_into_vtl1_heap_tuple << parameter_copied_into_tuple;
        }
        else
        {
            get_tuple_value = std::format(c_std_get_vtl1_input_tuple_value_for_enclave_to_host, index);

            // Copy the vtl1 input param value into the vtl0 heap version so we can forward it
            // to the vtl0 function.          
            parameter_copied_into_tuple = GetCopyStatement(
                parameter,
                parameter_type,
                size_to_copy,
                get_tuple_value,
                parameter.m_name,
                ParamCopyCase::CallToVtl0FromVtl1_CopyVtl1ParametersToVtl0Parameters);

            param_info.m_copy_vtl1_parameters_into_vtl0_heap_tuple << parameter_copied_into_tuple;
        }
    }

    CppCodeBuilder::FunctionParametersInfo CppCodeBuilder::GetParametersAndTupleInformation(
        const Function& function,
        CallFlowDirection call_direction)
    {
        FunctionParametersInfo param_info {};
        std::string separator {};
        size_t inout_out_return_tuple_index = 0U;

        // We copy function parameters into a tuple so we can forward them to a developer impl
        // function across the virtual trust boundary in one go. To do this we need to capture the types for
        // the parameters to forward, their names, and the types of parameters that need
        // to be returned e.g a function return value, in-out or out values. Indexes are used to index
        // the correct tuple value in relation to a forwarded parameter or in-out/out/return value.
        for (size_t params_index = 0U; params_index < function.m_parameters.size(); params_index++)
        {
            auto list_ender = (params_index + 1U < function.m_parameters.size()) ? "," : "";
            Declaration param_declaration = function.m_parameters[params_index];
            std::string type_without_pointer = GetSimpleTypeInfo(param_declaration.m_edl_type_info);
            auto type_info = GetTypeInfoForFunction(param_declaration);

            // We copy by value for in parameters or parameters without pointers.
            param_info.m_param_names_to_add_to_parameter_container << std::format(
                "{}{}",
                param_declaration.m_name,
                list_ender);

            param_info.m_param_names_to_add_to_initial_callers_parameter_container << std::format(
                "{}{}",
                param_declaration.m_name,
                list_ender);

            // remove the reference at the end of the type if it exists. We only need it to create function parameters,
            // otherwise we just need the type without the reference for parameters forwarding.
            if (type_info.back() == '&')
            {
                type_info.pop_back();
            }

            param_info.m_types_in_tuple << std::format("{}{}", type_info, list_ender);
            param_info.m_param_names_to_forward_to_dev_impl << std::format("{}{}", param_declaration.m_name, list_ender);
            std::string param_copy_size = GetSizeForCopy(param_declaration.m_attribute_info, type_without_pointer);

            // The data pointer parameters need to be copied into the correct virtual trust layer when we're initiating
            // a call that will pass function parameters across the boundary.
            SetupCopyOfForwardParameterStatements(
                param_declaration,
                params_index,
                type_without_pointer,
                param_copy_size,
                param_info,
                call_direction);

            if (param_declaration.IsInOutOrOutParameter())
            {
                auto out_param_allocation_statement = std::format(
                    c_allocate_memory_for_out_param,
                    param_declaration.m_name,
                    type_without_pointer,
                    param_copy_size,
                    param_declaration.m_name);

                // Build the statements to copy in-out/out parameters into/out of the original parameter. E.g If we have a vtl1
                // function parameter that we copied and forwarded to vtl0. We have to copy the vtl0 result back into the
                // original vtl1 parameter.
                SetupCopyOfReturnParameterStatements(
                    param_declaration,
                    params_index,
                    type_without_pointer,
                    param_copy_size,
                    param_info,
                    call_direction);

                // For reference parameters (in-out or out non pointer params) we need to copy the value into a return tuple
                // in the callee. Then in the caller copy the value from the returned tuple into the reference parameter.
                if (!param_declaration.HasPointer())
                {
                    separator = (inout_out_return_tuple_index) == 0 ? "" : ",";
                    param_info.m_types_to_return_in_tuple << std::format("{}{}", separator, type_without_pointer);
                    param_info.m_names_to_return_in_tuple << std::format("{}{}", separator, param_declaration.m_name);
                    param_info.m_return_tuple_param_indexes.push_back(
                        {param_declaration.m_name, inout_out_return_tuple_index}
                    );

                    inout_out_return_tuple_index++;
                }
            }
        }

        param_info.m_function_return_value = std::format("{}", GetSimpleTypeInfoWithPointerInfo(function.m_return_info.m_edl_type_info));

        bool is_void_function = function.m_return_info.m_edl_type_info.m_type_kind == EdlTypeKind::Void;
        param_info.m_are_return_params_needed = (!is_void_function || (inout_out_return_tuple_index > 0));
        param_info.m_function_return_type_void = is_void_function;

        // Finally add return value as the last value of the return tuple
        if (!is_void_function)
        {
            param_info.m_types_to_return_in_tuple << std::format(
                "{}{}",
                separator,
                param_info.m_function_return_value);

            param_info.m_names_to_return_in_tuple <<
                std::format("{}{}",
                separator,
                c_return_variable_name);
        }

        return param_info;
    }

    std::string  CppCodeBuilder::BuildFunctionParameters(
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
        std::string_view struct_field_name_to_forward,
        const Declaration& declaration,
        std::string_view all_params_separator,
        CppCodeBuilder::FunctionParametersInfo& param_info)
    {
        param_info.m_params_to_forward_to_dev_impl << FormatString(
            "{} {}->m_{}",
            all_params_separator,
            struct_field_name_to_forward,
            declaration.m_name);
    }

    void AddStatementToReturnParameterBackIntoOriginalParameter(
        const Declaration& declaration,
        CppCodeBuilder::FunctionParametersInfo& param_info)
    {
        bool is_complex_type = s_complex_types.contains(declaration.m_edl_type_info.m_type_kind);

        // Statements to copy return values out of out param struct and back into inout/out params
        if (declaration.IsEdlType(EdlTypeKind::Struct) || 
            declaration.IsInnerEdlType(EdlTypeKind::Struct) ||
            !declaration.m_array_dimensions.empty()||
            is_complex_type)
        {
            param_info.m_copy_values_from_out_struct_to_original_args << std::format(
                c_return_param_for_non_ptr_complex_type,
                declaration.m_name,
                declaration.m_name);
        }
        else
        {
            param_info.m_copy_values_from_out_struct_to_original_args << std::format(
                    c_return_param_for_non_ptr_non_complex_type,
                    declaration.m_name,
                    declaration.m_name);
        }
    }

    std::string CppCodeBuilder::AddAddressDeclaratorIfNecessary(const Declaration& declaration)
    {
        // For the To flatbuffer function that we generate that accepts multiple parameters we
        // want to pass these as pointers.
        if (declaration.m_array_dimensions.empty() && declaration.IsEdlType(EdlTypeKind::Struct))
        {
            return std::format("&{}",declaration.m_name);
        }


        return declaration.m_name;
    }

    void CppCodeBuilder::CaptureInformationAboutInParameter(
        const Function function,
        const Declaration& declaration,
        std::string_view all_params_separator,
        std::string_view in_and_inout_params_separator,
        CppCodeBuilder::FunctionParametersInfo& param_info)
    {
        auto name_with_address_declarator = AddAddressDeclaratorIfNecessary(declaration);
        param_info.m_all_param_names << std::format("{} {}", all_params_separator, name_with_address_declarator);
        param_info.m_in_inout_param_names << std::format("{} {}", in_and_inout_params_separator, declaration.m_name);
        AddParameterToTheForwardToDevImplList(c_dev_type_for_function_params_struct, declaration, all_params_separator, param_info);
    }

    void CppCodeBuilder::CaptureInformationAboutInOutParameter(
        const Declaration& declaration,
        std::string_view all_params_separator,
        std::string_view in_and_inout_params_separator,
        CppCodeBuilder::FunctionParametersInfo& param_info)
    {
        auto name_with_address_declarator = AddAddressDeclaratorIfNecessary(declaration);
        param_info.m_all_param_names << std::format("{} {}", all_params_separator, name_with_address_declarator);
        param_info.m_in_inout_param_names << std::format("{} {}", in_and_inout_params_separator, declaration.m_name);
        AddParameterToTheForwardToDevImplList(c_dev_type_for_function_params_struct, declaration, all_params_separator, param_info);
        AddStatementToReturnParameterBackIntoOriginalParameter(declaration, param_info);
    }

    void CppCodeBuilder::CaptureInformationAboutOutParameter(
        const Declaration& declaration,
        std::string_view all_params_separator,
        CppCodeBuilder::FunctionParametersInfo& param_info)
    {
        AddParameterToTheForwardToDevImplList(c_dev_type_for_function_params_struct, declaration, all_params_separator, param_info);
        AddStatementToReturnParameterBackIntoOriginalParameter(declaration, param_info);
    }

    CppCodeBuilder::FunctionParametersInfo CppCodeBuilder::GetInformationAboutParameters(
        const Function& function,
        std::string_view abi_function_name)
    {
        FunctionParametersInfo param_info {};
        size_t in_out_index = 0U;
        size_t in_index = 0U;
        size_t out_index = 0U;
        std::string in_and_inout_params_separator {};

        for (size_t params_index = 0U; params_index < function.m_parameters.size(); params_index++)
        {
            auto all_params_separator = (in_out_index == 0 && in_index == 0 && out_index == 0) ? "" : ",";
            in_and_inout_params_separator = (in_out_index == 0 && in_index == 0) ? "" : ",";
            const Declaration& declaration = function.m_parameters[params_index];

            if (declaration.IsInParameterOnly())
            {
                CaptureInformationAboutInParameter(
                    function,
                    declaration, 
                    all_params_separator,
                    in_and_inout_params_separator,
                    param_info);

                in_index++;
            }
            else if (declaration.IsInOutParameter())
            {
                CaptureInformationAboutInOutParameter(
                    declaration,
                    all_params_separator,
                    in_and_inout_params_separator,
                    param_info);  
                
                in_out_index++;
            }
            else
            {
                CaptureInformationAboutOutParameter(declaration, all_params_separator, param_info);
                out_index++;
            }
        }

        param_info.m_function_return_value = GetFullDeclarationType(function.m_return_info);
        auto& return_info = function.m_return_info.m_edl_type_info;
        bool is_void_function = return_info.m_type_kind == EdlTypeKind::Void;
        param_info.m_are_return_params_needed = !is_void_function || in_out_index > 0 || out_index > 0;
        param_info.m_function_return_type_void = is_void_function;

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

    std::string CppCodeBuilder::BuildHostToEnclaveInitialCallerFunction(
        const Function& function,
        std::string_view vtl1_generated_abi_function_name,
        std::string_view abi_function_to_call,
        const FunctionParametersInfo& param_info)
    {
        auto function_declaration = std::format(
            "{} {}{}",
            param_info.m_function_return_value,
            function.m_name,
            BuildFunctionParameters(function, param_info));

        std::string function_params_struct_type = std::format(c_function_args_struct, vtl1_generated_abi_function_name);

        // First create the using statements so we can use the type for forwarding parameters
        // and the type for returning parameters throughout the generated code.
        std::string return_parameters_using_statement = std::format(
            c_parameter_container_using_statement,
            function_params_struct_type);

        std::string parameters_using_statement = std::format(
            c_parameter_container_for_initial_host_to_enclave_call,
            function_params_struct_type,
            param_info.m_in_inout_param_names.str());

        std::ostringstream copy_and_using_statements;

        copy_and_using_statements << parameters_using_statement << return_parameters_using_statement;

        auto return_statement = c_empty_return;
        if (!param_info.m_function_return_type_void)
        {
            return_statement = c_return_value_to_initial_caller;
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
               c_setup_return_params_struct_for_vtl0_hostapp_to_enclave,
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

    std::string CppCodeBuilder::BuildEnclaveToHostInitialCallerFunction(
        const Function& function,
        std::string_view vtl0_generated_abi_function_name,
        std::string_view abi_function_to_call,
        const FunctionParametersInfo& param_info)
    {
        auto function_declaration = std::format(
            "{}{} {}{}",
            c_static_keyword,
            param_info.m_function_return_value,
            function.m_name,
            BuildFunctionParameters(function, param_info));

        std::string function_params_struct_type = std::format(c_function_args_struct, vtl0_generated_abi_function_name);

        // First create the using statements so we can use the type for forwarding parameters
        // and the type for returning parameters throughout the generated code.
        std::string parameters_using_statement = std::format(
            c_parameter_container_for_initial_enclave_to_host_call,
            function_params_struct_type,
            param_info.m_in_inout_param_names.str());

        std::string return_parameters_using_statement = std::format(
            c_parameter_container_using_statement,
            function_params_struct_type);

        std::ostringstream copy_and_using_statements;

        copy_and_using_statements << parameters_using_statement << return_parameters_using_statement;

        auto return_statement = c_empty_return;

        if (!param_info.m_function_return_type_void)
        {
            return_statement = c_return_value_to_initial_caller;
        }

        std::string final_part_of_function {};

        if (param_info.m_are_return_params_needed)
        {
            std::ostringstream copy_statements_for_return_struct;
            copy_statements_for_return_struct <<
                param_info.m_copy_values_from_out_struct_to_original_args.str();
            copy_statements_for_return_struct << return_statement;

            final_part_of_function = std::format(
                c_setup_return_params_struct_for_vtl0_enclave_to_host,
                function_params_struct_type,
                copy_statements_for_return_struct.str());
        }
        else
        {
            final_part_of_function = return_statement;
        }

        return std::format(
            c_initial_caller_function_body,
            function_declaration,
            copy_and_using_statements.str(),
            abi_function_to_call,
            final_part_of_function);
    }

    std::string CppCodeBuilder::BuildTrustBoundaryFunction(
        const Function& function,
        std::string_view boundary_function_name,
        std::string_view abi_function_to_call,
        bool is_vtl0_callback,
        const FunctionParametersInfo& param_info)
    {
        std::string function_in_params_struct_type = std::format(c_function_args_struct, boundary_function_name);

        std::string params_using_statement = std::format(
            c_parameter_container_type,
            function_in_params_struct_type);

        std::string return_params_using_statement = std::format(
            c_parameter_container_type,
            function_in_params_struct_type);

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

    std::string CppCodeBuilder::BuildVtl0AbiImplFunctionForEnclaveToHost(
        const Function& function,
        std::string_view abi_function_name,
        std::string_view call_impl_str,
        const FunctionParametersInfo& param_info)
    {
        std::string function_in_params_struct_type = std::format(c_function_args_struct, abi_function_name);

        auto abi_parameters = std::format(c_abi_function_parameters_receiver, abi_function_name);
        std::string params_to_forward = param_info.m_params_to_forward_to_dev_impl.str();
        std::ostringstream function_body {};

        std::ostringstream return_parameters_for_enclave_to_host {};

        if (param_info.m_are_return_params_needed)
        {
            return_parameters_for_enclave_to_host << std::format(
                c_setup_copy_of_return_parameters_enclave_to_host,
                function_in_params_struct_type);
        }

        std::string_view return_statement {};
        if (param_info.m_function_return_type_void)
        {
            return_statement = c_abi_func_return_null_when_void;
        }
        else
        {
            return_statement = c_abi_func_return_value_for_enclave_to_host;
        }

        function_body << FormatString(
            return_statement,
            function_in_params_struct_type,
            call_impl_str,
            params_to_forward,
            return_parameters_for_enclave_to_host.str());


        return std::format(
            c_generated_abi_impl_function,
            abi_function_name,
            abi_parameters,
            function_body.str());
    }

    std::string CppCodeBuilder::BuildVtl1AbiImplFunctionForHostToEnclave(
        const Function& function,
        std::string_view abi_function_name,
        std::string_view call_impl_str,
        const FunctionParametersInfo& param_info)
    {
        std::string function_in_params_struct_type = std::format(c_function_args_struct, abi_function_name);

        auto abi_parameters = std::format(c_abi_function_parameters_receiver, abi_function_name);
        std::ostringstream function_body {};

        std::string params_to_forward = param_info.m_params_to_forward_to_dev_impl.str();
        std::ostringstream return_parameters_for_host_to_enclave {};

        if (param_info.m_are_return_params_needed)
        {
            return_parameters_for_host_to_enclave << std::format(
                c_setup_copy_of_return_parameters_host_to_enclave,
                function_in_params_struct_type);
        }

        std::string_view return_statement{};
        if (param_info.m_function_return_type_void)
        {
            return_statement = c_abi_func_return_null_when_void;
        }
        else
        {
            return_statement = c_abi_func_return_value_for_host_enclave;
        }

        function_body << FormatString(
            return_statement,
            function_in_params_struct_type,
            call_impl_str,
            params_to_forward,
            return_parameters_for_host_to_enclave.str());


        return std::format(
            c_generated_abi_impl_function,
            abi_function_name,
            abi_parameters,
            function_body.str());
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
        std::ostringstream& flatbuffer_content,
        std::ostringstream& developer_structs,
        const std::unordered_map<std::string, std::shared_ptr<DeveloperType>>& developer_types,
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
            auto abi_function_name = GetFunctionNameForAbi(function.m_name);
            auto param_info = GetInformationAboutParameters(function, abi_function_name);
            auto vtl1_exported_func_name = std::format(c_generated_stub_name, abi_function_name);
            auto vtl0_call_to_vtl1_export = std::format(
                c_vtl0_call_to_vtl1_export,
                vtl1_exported_func_name);

            auto [table, built_struct] = BuildFlatbufferConversionStructsAndTables(function, abi_function_name, param_info);
            
            flatbuffer_content << table.str();
            developer_structs << built_struct.str();

            // This is the vtl0 abi function that the developer will call into to start the flow
            // of calling their vtl1 enclave function impl.
            vtl0_side_of_vtl1_developer_impl_functions << BuildHostToEnclaveInitialCallerFunction(
                function,
                abi_function_name,
                vtl0_call_to_vtl1_export,
                param_info);

            auto vtl1_call_to_vtl1_export = std::format(
                c_vtl1_call_to_vtl1_export,
                abi_function_name,
                abi_function_name);

            // This is the vtl0 function that is exported by the enclave and called via a
            // CallEnclave call by the abi.
            vtl1_abi_boundary_functions << BuildTrustBoundaryFunction(
                function,
                abi_function_name,
                vtl1_call_to_vtl1_export,
                false,
                param_info);

            auto developer_function_to_call = std::format(c_vtl1_abi_function_call_to_dev_impl, function.m_name);

            // This is the vtl1 abi function that will call the developers vtl1 function implementation.
            std::string vtl1_abi_impl_definition = BuildVtl1AbiImplFunctionForHostToEnclave(
                function,
                abi_function_name,
                developer_function_to_call,
                param_info);

            // VTL1 enclave function that the developer will implement. It is called by the vtl1
            // abi function impl for this particular function.
            vtl1_developer_declaration_functions << std::format(
                c_function_declaration,
                param_info.m_function_return_value,
                function.m_name,
                BuildFunctionParameters(function, param_info));

            vtl1_abi_impl_functions << vtl1_abi_impl_definition;

            vtl1_generated_module_exports << std::format(c_exported_function_in_module, abi_function_name);
        }

        vtl0_class_public_portion << vtl0_side_of_vtl1_developer_impl_functions.str();

        // Add register callbacks abi export to module file and add it at the end of the vtl1 stubs file.
        vtl1_generated_module_exports << c_vtl1_register_callbacks_abi_export_name;
        vtl1_abi_boundary_functions << c_vtl1_register_callbacks_abi_export;

        auto vtl1_stubs_in_namespace =
            std::format(c_vtl1_enclave_stub_namespace, generated_namespace, vtl1_abi_boundary_functions.str());

        // Add register callback tables.
        flatbuffer_content << c_flatbuffer_register_callback_tables;
        
        return HostToEnclaveContent {
            std::move(vtl0_class_public_portion),
            std::format("{}{}{}",c_autogen_header_string, c_vtl1_enclave_stub_includes, vtl1_stubs_in_namespace),
            std::move(vtl1_developer_declaration_functions),
            std::move(vtl1_abi_impl_functions),
            BuildEnclaveModuleDefinitionFile(vtl1_generated_module_exports.str())
        };
    }

    CppCodeBuilder::EnclaveToHostContent CppCodeBuilder::BuildEnclaveToHostFunctions(
        std::ostringstream& flatbuffer_content,
        std::ostringstream& developer_structs,
        const std::unordered_map<std::string, std::shared_ptr<DeveloperType>>& developer_types,
        std::unordered_map<std::string, Function>& functions)
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
            auto param_info = GetInformationAboutParameters(function, abi_function_name);
            
            auto [table, built_struct] = BuildFlatbufferConversionStructsAndTables(function, abi_function_name, param_info);

            flatbuffer_content << table.str();
            developer_structs << built_struct.str();

            auto vtl1_call_to_vtl0_callback = std::format(
                c_vtl1_call_to_vtl0_callback,
                vtl1_map_function_index++);

            // This is the vtl1 static function that the developer will call into from vtl1 with the
            // same parameters as their vtl0 callback function. This initiates the abi call from vtl1 
            // to the vtl0 abi boundary function for this specific function.
            vtl1_side_of_vtl0_callback_functions << BuildEnclaveToHostInitialCallerFunction(
                function,
                abi_function_name,
                vtl1_call_to_vtl0_callback,
                param_info);

            auto vtl0_call_to_vtl0_callback = std::format(
                c_vtl0_call_to_vtl0_callback,
                abi_function_name,
                abi_function_name);

            // This is the vtl0 callback that will call into our abi vtl0 callback implementation.
            // This callback is what vtl1 will call with CallEnclave.
            vtl0_abi_boundary_functions << BuildTrustBoundaryFunction(
                function,
                abi_function_name,
                vtl0_call_to_vtl0_callback,
                true,
                param_info);

            // This is our vtl0 abi callback implementation that will finally pass the parameters
            // to the developers vtl0 impl function.
            vtl0_abi_impl_callback_functions << BuildVtl0AbiImplFunctionForEnclaveToHost(
                function,
                abi_function_name,
                function.m_name,
                param_info);

            // This is the developers vtl0 impl function. The developer will implement this static class
            // method.
            vtl0_developer_declaration_functions << std::format(
                c_static_declaration,
                param_info.m_function_return_value,
                function.m_name,
                BuildFunctionParameters(function, param_info));

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
}
