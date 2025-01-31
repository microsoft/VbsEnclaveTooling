// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once 
#include <pch.h>
#include <Edl\Structures.h>
#include <Edl\Utils.h>
#include <CodeGeneration\Contants.h>
#include <CodeGeneration\CodeGeneration.h>

using namespace EdlProcessor;

namespace CodeGeneration
{
    std::string CppCodeBuilder::BuildDeveloperTypesHeader(
        const std::unordered_map<std::string, std::shared_ptr<DeveloperType>>& developer_types)
    {
        std::string types_header {};

        for (auto&& [name, type] : developer_types)
        {
            types_header += BuildDeveloperType(*type);
        }

        auto start_of_file = std::format(c_developer_types_start_of_file, c_autogen_header_string);
        start_of_file = std::format(c_developer_types_start_of_file, c_autogen_header_string);
        auto body = std::format(c_developer_types_namespace, types_header);

        return std::format("{}{}\n", start_of_file, body);
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

    std::string CppCodeBuilder::GetTypeInfoForFunction(const Declaration& declaration)
    {
        EdlTypeInfo& info = *(declaration.m_edl_type_info);
        std::string type = GetSimpleTypeInfo(info);;

        if (!declaration.m_array_dimensions.empty())
        {
            auto type_info = GetSimpleTypeInfo(info);
            type = BuildStdArrayType(type_info, declaration.m_array_dimensions);
        }        

        std::string pointer = (declaration.HasPointer()) ? "*" : "";
        bool parent_is_function = declaration.m_parent_kind == DeclarationParentKind::Function;

        if (declaration.m_attribute_info && parent_is_function)
        {
            ParsedAttributeInfo attribute = declaration.m_attribute_info.value();
            std::string puncutator = (!pointer.empty()) ? pointer : "";

            if (attribute.m_in_present && attribute.m_out_present)
            {
                return std::format("{}{}", type, puncutator);
            }
            else if (attribute.m_out_present)
            {
                // Double pointers for out parameters which can be used with vtl0/vtl1 smart pointers.
                return std::format("{}{}{}", type, ASTERISK, ASTERISK);
            }

        }

        return std::format("{}{}", type, pointer);
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

    std::string CppCodeBuilder::BuildArrayType(const Declaration& declaration)
    {
        if (declaration.m_parent_kind == DeclarationParentKind::Function)
        {
            return std::format("{} {}", GetTypeInfoForFunction(declaration), declaration.m_name);
        }

        EdlTypeInfo& info = *(declaration.m_edl_type_info);
        auto type_info = GetSimpleTypeInfo(info);
        auto array_info = BuildStdArrayType(type_info, declaration.m_array_dimensions);
        return std::format("{} {}", array_info, declaration.m_name);
    }

    std::string CppCodeBuilder::BuildNonArrayType(const Declaration& declaration)
    {
        EdlTypeInfo& info = *(declaration.m_edl_type_info);

        if (declaration.m_parent_kind == DeclarationParentKind::Function)
        {
            return std::format("{} {}", GetTypeInfoForFunction(declaration), declaration.m_name);
        }

        auto pointer = info.m_extended_type_info ? info.m_extended_type_info->m_name : "";
        return std::format("{}{} {}", GetSimpleTypeInfo(info), pointer, declaration.m_name);
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
                BuildStructFieldOrFunctionParameter(field),
                SEMI_COLON);
        }

        return std::format("\n{}\n{}{}{}{}\n",
            c_pragma_pack,
            struct_header, 
            struct_body, 
            struct_footer, 
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

    std::string  CppCodeBuilder::BuildFunctionParameters(const Function& function)
    {
       
        std::string function_parameters = "(";

        if (function.m_parameters.empty())
        {
            function_parameters += c_void_type_function_parameter;
        }

        for (auto i = 0U; i < function.m_parameters.size(); i++)
        {
            Declaration declaration = function.m_parameters[i];
            auto parameter = BuildStructFieldOrFunctionParameter(declaration);
            auto complete_parameter = AddSalToParameter(declaration, parameter);

            if (i + 1 < function.m_parameters.size())
            {
                function_parameters += std::format("{}{} ", complete_parameter, COMMA);
            }
            else
            {
                function_parameters += std::format("{}", complete_parameter);
            }
        }
        
        function_parameters += ")";

        return function_parameters;
    }

    std::tuple<std::string, std::string, std::string> CppCodeBuilder::GetParametersAndTupleInformation(const Function& function)
    {
        // Parameters will contain SAL and type information.
        std::string function_parameter_tuple_types {};
        std::string tuple_definition {};

        // List without SAL and type, just the parameter name.
        std::string plain_parameter_list {};
        auto list_ender = ",";

        for (auto i = 0U; i < function.m_parameters.size(); i++)
        {
            list_ender = (i + 1 < function.m_parameters.size()) ? list_ender : "";
            Declaration field = function.m_parameters[i];
            auto type_info = GetTypeInfoForFunction(field);
            function_parameter_tuple_types += std::format(c_function_parameter_type, type_info, list_ender);
            tuple_definition += std::format(c_function_tuple_definition, type_info, field.m_name, list_ender);
            plain_parameter_list += std::format("{}{}", field.m_name, list_ender);
        }

        if (function.m_parameters.empty())
        {
            function_parameter_tuple_types = std::format(c_function_parameter_type, c_void_type_function_parameter, "");
            tuple_definition = std::format(c_function_tuple_definition, c_void_type_function_parameter, "", "");
        }

        return {function_parameter_tuple_types, tuple_definition, plain_parameter_list};

    }

    CppCodeBuilder::TrustFunctionHeaders CppCodeBuilder::BuildHostToEnclaveFunctions(
        std::string_view edl_file_name, 
        const std::unordered_map<std::string, Function>& functions)
    {
        // The VTL0 side contains a class and within it methods that call a VTL1 stub function via CallEnclave()
        auto vtl0_class_name = std::format("{}Wrapper", edl_file_name);
        auto [vtl0_class_header, vtl0_class_body, vtl0_class_footer] = BuildStartOfDefinition(EDL_STRUCT_KEYWORD, vtl0_class_name);
        vtl0_class_body += std::format("\n{}{}(LPVOID enclave) : m_enclave(enclave){{}}\n\n", c_four_spaces, vtl0_class_name);

        // The VTL1 stub functions that will ultimately call the VTL1 implementation that the developer will implement within
        // the enclave
        std::string vtl1_stub_functions {};

        std::string vtl1_developer_impl_functions {};

        std::string vtl1_abi_impl_functions {};

        std::string generated_function_parameter_verifier {};

        std::string vtl1_generated_module_exports {};

        for (auto&& [name, function] : functions)
        {
            auto return_info = *(function.m_return_info);

            // All vtl0 stub functions that return a value return a vtl0 pointer to vtl0 memory created with HeapAlloc. So, we
            // specify a pointer as the return value regardless of whether it appears in the edl or not. E.g uint32_t myFunc();
            // becomes uint32_t* myFunc() for all the stub and impl functions in vtl0 and vtl1.
            auto pointer = (return_info.m_type_kind != EdlTypeKind::Void) ? "*" : "";

            auto return_value = std::format("{}{}", GetSimpleTypeInfo(return_info), pointer);
            auto [parameter_tuple_types, tuple_definition, parameter_list] = GetParametersAndTupleInformation(function);

            vtl0_class_body += BuildVTL0HostToEnclaveStubFunction(function, return_value, parameter_tuple_types, tuple_definition);

            vtl1_stub_functions += BuildVTL1HostToEnclaveStubFunction(function, return_value, parameter_tuple_types, tuple_definition);

            auto [abi_impl_definition, developer_impl_declaration] = BuildVTL1HostToEnclaveImplFunction(function, return_value, parameter_list);

            vtl1_developer_impl_functions += developer_impl_declaration;

            vtl1_abi_impl_functions += abi_impl_definition;

            vtl1_generated_module_exports += std::format("{}{}{}_Generated_Stub\n", c_four_spaces, c_four_spaces, function.m_name);

            generated_function_parameter_verifier += BuildCopyAndVerifyFunction(function);
        }

        vtl0_class_body += std::format("\nprivate:\n {}LPVOID m_enclave{{}};\n", c_four_spaces);

        auto full_class = std::format("{}{}{}",
           vtl0_class_header,
           vtl0_class_body,
           vtl0_class_footer);

        auto vtl0_class_in_namespace = std::format(c_vtl0_class_hostapp_namespace, edl_file_name, full_class);
        auto vtl1_stub_functions_in_namespace = std::format(c_vtl1_enclave_stub_namespace, edl_file_name, vtl1_stub_functions);
        auto vtl1_developer_impls_in_namespace = std::format(c_vtl1_enclave_func_impl_namespace, edl_file_name, vtl1_developer_impl_functions , vtl1_abi_impl_functions);
        auto vtl1_verifiers_in_namespace = std::format(c_vtl1_enclave_parameter_verifier_namespace, edl_file_name, generated_function_parameter_verifier);

        return TrustFunctionHeaders {
            std::format("{}{}{}",c_autogen_header_string, c_vtl0_class_start_of_file, vtl0_class_in_namespace),
            std::format("{}{}{}",c_autogen_header_string, c_vtl1_enclave_stub_start_of_file, vtl1_stub_functions_in_namespace),
            std::format("{}{}{}",c_autogen_header_string, c_vtl1_enclave_func_impl_start_of_file, vtl1_developer_impls_in_namespace),
            BuildEnclaveModuleDefinitionFile(vtl1_generated_module_exports),
            std::format("{}{}{}",c_autogen_header_string, c_vtl1_enclave_verifier_start_of_file, vtl1_verifiers_in_namespace),
        };
    }

    std::string CppCodeBuilder::BuildVTL0HostToEnclaveStubFunctionBody(
        const Function& function,
        std::string_view return_value,
        std::string_view parameter_tuple_type,
        std::string_view tuple_definition)
    {
        std::string full_parameters_string = std::format(
            c_parameter_container,
            parameter_tuple_type,
            tuple_definition);

        if (function.m_return_info->m_type_kind == EdlTypeKind::Void)
        {
            return std::format(
                 c_from_class_call_vtl1_stub_no_result,
                 full_parameters_string,
                 std::format(c_generated_stub_name, function.m_name));
        }
        else
        {
            return std::format(
                 c_from_class_call_vtl1_stub_with_result,
                 full_parameters_string,
                 return_value,
                 std::format(c_generated_stub_name,function.m_name));
        }
    }

    std::string CppCodeBuilder::BuildVTL0HostToEnclaveStubFunction(
        const Function& function,
        std::string_view return_value,
        std::string_view parameter_tuple_type,
        std::string_view tuple_definition)
    {
        auto function_declaration = std::format("{} {}{}", return_value, function.m_name, BuildFunctionParameters(function));;
        auto function_body = BuildVTL0HostToEnclaveStubFunctionBody(function, return_value, parameter_tuple_type, tuple_definition);
        
        return std::format("\n{}{}\n",
           function_declaration,
           function_body);
    }

    std::string CppCodeBuilder::BuildVTL1HostToEnclaveStubFunction(
        const Function& function,
            std::string_view return_value,
            std::string_view parameter_tuple_type,
            std::string_view tuple_definition)
    {
        std::string using_function_statement = std::format(
            c_parameter_container_type,
            parameter_tuple_type);
        
        std::string inner_body{};

        if (function.m_return_info->m_type_kind == EdlTypeKind::Void)
        {
            inner_body = std::format(
                c_inner_abi_function_no_result,
                using_function_statement,
                function.m_name,
                function.m_name);
        }
        else
        {
            inner_body = std::format(
                c_inner_abi_function_with_result,
                using_function_statement,
                return_value,
                function.m_name,
                function.m_name);
        }

        std::string outer_body = std::format(
            c_outer_abi_function,
            function.m_name,
            inner_body);

        return outer_body;
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
            pos = module_def.find("//", pos + 1);
        }

        return module_def;
    }

    std::tuple<std::string, std::string> CppCodeBuilder::BuildVTL1HostToEnclaveImplFunction(
        const Function& function, 
        std::string_view return_value, 
        std::string_view parameter_list_without_types)
    {
        auto abi_parameters = BuildFunctionParameters(function);
        auto developer_impl_parameters = (abi_parameters == "(__VoidType__)") ? "()" : abi_parameters;
        auto is_void_return = (function.m_return_info->m_type_kind == EdlTypeKind::Void);
        auto return_part_of_statement = (is_void_return) ? "" : "return";

        auto call_developer_impl_declaration = std::format(
            "{} {}::{}({});", 
            return_part_of_statement,
            c_developer_impl_namespace,
            function.m_name,
            parameter_list_without_types);

        auto abi_impl_definition = std::format(
            c_generated_abi_impl_function,
            return_value,
            function.m_name,
            abi_parameters,
            call_developer_impl_declaration); 
            
        auto developer_impl_declaration = std::format(
            c_generated_developer_impl_function,
            return_value,
            function.m_name,
            developer_impl_parameters);

        return { abi_impl_definition, developer_impl_declaration};
    }   

    // See comment in c_generated_function_parameter_verifier. Once Flatbuffer support is added this will be updated
    // to actually verify the parameters. For now, we just return the parameters back to the caller as is. Note:
    // the caller of this is the ABI who already copied the parameters 
    std::string CppCodeBuilder::BuildCopyAndVerifyFunction(const Function& function)
    {
        return std::format(
            c_generated_function_parameter_verifier,
            function.m_name);
    }
}
