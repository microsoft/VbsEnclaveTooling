// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once 
#include <pch.h>
#include <CodeGeneration\Common\Helpers.h>
#include <CodeGeneration\Rust\Constants.h>
#include <Edl\Structures.h>

using namespace EdlProcessor;

namespace CodeGeneration::Rust
{
    using namespace CodeGeneration::Common;

    inline std::string EdlTypeToRustType(const EdlTypeInfo& info)
    {
        switch (info.m_type_kind)
        {
        case EdlTypeKind::UInt8:
            return "u8";
        case EdlTypeKind::UInt16:
            return "u16";
        case EdlTypeKind::UInt32:
            return "u32";
        case EdlTypeKind::Int8:
            return "i8";
        case EdlTypeKind::Int16:
            return "i16";
        case EdlTypeKind::Int32:
        case EdlTypeKind::HRESULT:
            return "i32";
        case EdlTypeKind::Int64:
            return "i64";
        case EdlTypeKind::UInt64:
        case EdlTypeKind::UIntPtr:
            return "u64";
        case EdlTypeKind::String:
            return "String";
        case EdlTypeKind::WString:
            return "edl::WString";
        default:
            return info.m_name;
        }
    }

    inline std::string AddVectorEncapulation(const Declaration& vector_declaration)
    {
        auto inner_type = vector_declaration.m_edl_type_info.inner_type;
        auto inner_type_name = EdlTypeToRustType(*inner_type);
        return std::format("Vec<{}>", inner_type_name);
    }

    inline std::string AddOptionalEncapulation(const Declaration& optional_declaration)
    {
        auto inner_type = optional_declaration.m_edl_type_info.inner_type;
        auto inner_type_name = EdlTypeToRustType(*inner_type);

        return std::format("Option<{}>", inner_type_name);
    }

    inline std::string GetFullDeclarationType(const Declaration& declaration)
    {
        EdlTypeKind type_kind = declaration.m_edl_type_info.m_type_kind;
        std::string type_name = EdlTypeToRustType(declaration.m_edl_type_info);

        if (type_kind == EdlTypeKind::Void)
        {
            return "()";
        }

        if (declaration.IsEdlType(EdlTypeKind::Vector))
        {
            return AddVectorEncapulation(declaration);
        }

        if (!declaration.m_array_dimensions.empty())
        {
            return std::format(c_array_initializer, type_name, declaration.m_array_dimensions.front());
        }

        if (declaration.IsEdlType(EdlTypeKind::Optional))
        {
            return AddOptionalEncapulation(declaration);
        }

        return type_name;
    }

    inline std::string GetParameterSyntax(const Declaration& declaration)
    {
        // Primitive in parameters should not have a borrow declarator.
        if (declaration.IsInParameterOnly() && declaration.IsPrimitiveType())
        {
            return {};
        }

        // Mutable borrow.
        if (declaration.IsInOutParameter() || declaration.IsOutParameter())
        {
            return "&mut ";
        }

        // Const borrow for all other parameters.
        return "&";
    }

    inline std::string GetParameterForFunction(const Declaration& declaration)
    {
        std::string full_type = GetFullDeclarationType(declaration);
        std::string param_declarator = GetParameterSyntax(declaration);

        return std::format("{}: {}{}", declaration.m_name, param_declarator, full_type);
    }

    inline std::string GetEnumValueExpression(const EnumType& enum_value)
    {
        if (enum_value.m_value)
        {
            // Value was explicitly assigned
            return enum_value.m_value.value();
        }

        if (enum_value.m_is_hex)
        {
            return Uint64ToHex(enum_value.m_declared_position);
        }

        return Uint64ToDecimal(enum_value.m_declared_position);
    }

    inline std::string GenerateConstantsFromAnonEnum(const DeveloperType& developer_types)
    {
        std::ostringstream pub_constants {};
        for (auto& enum_value : developer_types.m_items.values())
        {
            pub_constants << std::format(
                "\npub const {}: u32 = {};\n",
                enum_value.m_name,
                GetEnumValueExpression(enum_value)
            );
        }
        return pub_constants.str();
    }

    inline std::string GenerateFunctionParametersList(const std::vector<Declaration>& parameters)
    {
        std::ostringstream parameter_list {};
        for (auto i = 0U; i < parameters.size(); i++)
        {
            parameter_list << GetParameterForFunction(parameters[i]);
            if (i < parameters.size() - 1)
            {
                parameter_list << ", ";
            }
        }
        return parameter_list.str();
    }

    inline std::string GetVecParamToFlatbufferStatement(
        std::string first_part,
        const Declaration& param)
    {
        auto inner_type = param.m_edl_type_info.inner_type;
        if (param.IsEdlType(EdlTypeKind::String))
        {
            return first_part + ".iter().copied().map(String::from).collect();\n";
        }

        return first_part + ".iter().cloned().map(Into::into).collect();\n";
    }

    inline std::string GetParamToFlatbufferStatements(
        uint32_t indentation,
        const std::vector<Declaration>& parameters)
    {
        std::ostringstream conversion_statements {};
        auto tabs = GenerateTabs(indentation);
        for (auto& param : parameters)
        {
            auto first_part = std::format("{}fb_native.m_{} = {}", tabs, param.m_name, param.m_name);

            if (param.IsEdlType(EdlTypeKind::Vector) || !param.m_array_dimensions.empty())
            {
                conversion_statements << GetVecParamToFlatbufferStatement(first_part, param);
            }
            else
            {
                conversion_statements << first_part + ".clone().into();\n";
            }
        }

        return conversion_statements.str();
    }

    inline std::string GetReturnedDevTypeToParamStatements(
        uint32_t indentation,
        const std::vector<Declaration>& parameters)
    {
        std::ostringstream param_update_statements {};
        auto tabs = GenerateTabs(indentation);
        for (auto& param : parameters)
        {
            if (param.IsInOutOrOutParameter())
            {
                param_update_statements << std::format("{}{} = result.{}\n", tabs, param.m_name, param.m_name);
            }
        }

        return param_update_statements.str();
    }

    inline std::string GetClosureFunctionStatement(const Function& function)
    {
        std::ostringstream abi_struct_fields {};
        for (auto i = 0U; i < function.m_parameters.size(); i++)
        {
            Declaration param = function.m_parameters[i];
            abi_struct_fields << std::format("{}{}", GetParameterSyntax(param), param.m_name);
            if (i < function.m_parameters.size() - 1)
            {
                abi_struct_fields << ", ";
            }
        }

        if (function.m_return_info.IsEdlType(EdlTypeKind::Void))
        {
            return std::format(c_closure_content_no_result, function.m_name, abi_struct_fields .str());
        }

        return std::format(c_closure_content_with_result, function.m_name, abi_struct_fields .str());
    }
}
