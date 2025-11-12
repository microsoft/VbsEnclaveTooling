// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once 
#include <pch.h>
#include <CmdlineParsingHelpers.h>
#include <CodeGeneration\Common\Helpers.h>
#include <CodeGeneration\Rust\Constants.h>
#include <Edl\Structures.h>

using namespace EdlProcessor;
using namespace CmdlineParsingHelpers;

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

        if (declaration.IsEdlType(EdlTypeKind::Optional))
        {
            return AddOptionalEncapulation(declaration);
        }

        if (declaration.IsEdlType(EdlTypeKind::Vector))
        {
            type_name = AddVectorEncapulation(declaration);
        }

        if (!declaration.m_array_dimensions.empty())
        {
            type_name = std::format(c_array_initializer, type_name, declaration.m_array_dimensions.front());
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

    inline std::string TransformCaseToUpper(const std::string& str)
    {
        std::string result(str);
        std::transform(
            result.begin(), result.end(), result.begin(),
            [] (unsigned char c) { return std::toupper(c); }
        );
        return result;
    }

    inline std::string GenerateConstantsFromAnonEnum(const DeveloperType& developer_types)
    {
        std::ostringstream pub_constants {};
        for (auto& enum_value : developer_types.m_items.values())
        {
            // Rust expects constants to be all uppercased
            pub_constants << std::format(
                "\npub const {}: u32 = {};\n",
                TransformCaseToUpper(enum_value.m_name),
                GetEnumValueExpression(enum_value)
            );
        }
        return pub_constants.str();
    }
}
