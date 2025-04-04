// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once 
#include <pch.h>
#include <Edl\Structures.h>
#include <Edl\Utils.h>
#include <CodeGeneration\Contants.h>
#include <CodeGeneration\CodeGeneration.h>
#include <CodeGeneration\CodeGenerationHelpers.h>
#include <CodeGeneration\Flatbuffers\Cpp\CppContants.h>
#include <CodeGeneration\Flatbuffers\Cpp\ConversionFunctionHelpers.h>
#include <CodeGeneration\Flatbuffers\BuilderHelpers.h>

#include <sstream>

using namespace EdlProcessor;

namespace CodeGeneration::Flatbuffers::Cpp
{

    std::string BuildConversionFunctionBody(
        const std::vector<Declaration>& fields,
        FlatbufferConversionKind conversion_kind,
        FlatbufferStructFieldsModifier modifier)
    {
        std::ostringstream copy_statements {};

        for (auto& declaration : fields)
        {
            FlatbufferSupportedTypes flatbuffer_type {};

            if (!declaration.m_array_dimensions.empty())
            {
                if (declaration.IsEdlType(EdlTypeKind::Struct))
                {
                    flatbuffer_type = FlatbufferSupportedTypes::LinearArrayStructs;
                }
                else if (declaration.IsEdlType(EdlTypeKind::WString))
                {
                    flatbuffer_type = FlatbufferSupportedTypes::LinearArrayWString;
                }
                else if (declaration.IsEdlType(EdlTypeKind::Enum))
                {
                    flatbuffer_type = FlatbufferSupportedTypes::LinearArrayEnums;
                }
                else
                {
                    flatbuffer_type = FlatbufferSupportedTypes::LinearArrayBasic;
                }
            }
            else if (declaration.HasPointer())
            {
                if (declaration.IsEdlType(EdlTypeKind::Enum))
                {
                    flatbuffer_type = FlatbufferSupportedTypes::PtrForEnum;
                }
                else  if (declaration.IsEdlType(EdlTypeKind::Struct))
                {
                    flatbuffer_type = FlatbufferSupportedTypes::PtrForStruct;
                }
                else
                {
                    flatbuffer_type = FlatbufferSupportedTypes::PtrForPrimitive;
                }
            }
            else
            {
                flatbuffer_type = GetSupportedFlatbufferTypeKind(declaration);
            }

            std::string flatbuffer_side = std::format("flatbuffer.{}", declaration.m_name);
            std::string struct_side = std::format("dev_type.{}", declaration.m_name);
            FieldNameDataForCopyStatements variable_names {flatbuffer_side, struct_side, modifier};

            if (conversion_kind == FlatbufferConversionKind::ToFlatbuffer &&
                modifier == FlatbufferStructFieldsModifier::AbiToFlatbufferMultipleParameters)
            {
                variable_names = {flatbuffer_side, declaration.m_name, modifier};
                copy_statements << GetDevTypeToFlatbufferCopyStatements(declaration, flatbuffer_type, variable_names);
            }
            else if (conversion_kind == FlatbufferConversionKind::ToFlatbuffer)
            {
                copy_statements << GetDevTypeToFlatbufferCopyStatements(declaration, flatbuffer_type, variable_names);
            }

            if (conversion_kind == FlatbufferConversionKind::ToDevType)
            {
                copy_statements << GetFlatbufferToDevTypeCopyStatements(declaration, flatbuffer_type, variable_names);
            }
        }

        return copy_statements.str();
    }

    std::string FormatStringForDevTypeToFlatbufferPtr(
        std::string_view last_part,
        const FieldNameDataForCopyStatements& field_names)
    {
        return FormatString(
             c_dev_type_to_flatbuffer_conversion_ptr_base_smartptr,
             field_names.m_struct,
             last_part);
    }

    std::string GetDevTypeToFlatbufferCopyStatements(
        const Declaration& declaration,
        FlatbufferSupportedTypes type_kind,
        FieldNameDataForCopyStatements field_names)
    {
        std::string_view string_to_format = c_dev_type_to_flatbuffer_statement_map.at(type_kind);
        std::string_view field_name = declaration.m_name;
        std::string_view obj_type = declaration.m_edl_type_info.m_name;
        std::string buf_size = GetSizeFromAttribute(declaration);
        std::string_view flatbuffer_field = field_names.m_flatbuffer;
        std::string_view struct_field = field_names.m_struct;

        if (type_kind == FlatbufferSupportedTypes::LinearArrayBasic)
        {
            return FormatString(string_to_format, flatbuffer_field, struct_field, struct_field);
        }
        else if (type_kind == FlatbufferSupportedTypes::LinearArrayStructs)
        {
            return FormatString(
                string_to_format,
                flatbuffer_field,
                struct_field,
                struct_field,
                struct_field,
                flatbuffer_field,
                obj_type);
        }
        else if (type_kind == FlatbufferSupportedTypes::LinearArrayEnums)
        {
            return FormatString(string_to_format,
                flatbuffer_field,
                struct_field,
                struct_field,
                struct_field,
                flatbuffer_field,
                obj_type,
                obj_type);
        }
        else if (type_kind == FlatbufferSupportedTypes::LinearArrayWString)
        {
            return FormatString(string_to_format, flatbuffer_field, struct_field, struct_field, struct_field, flatbuffer_field);
        }
        else if (type_kind == FlatbufferSupportedTypes::LinearVectorBasic)
        {
            return FormatString(string_to_format, flatbuffer_field, struct_field, struct_field);
        }
        else if (type_kind == FlatbufferSupportedTypes::LinearVectorEnums)
        {
            return FormatString(
               string_to_format,
               flatbuffer_field,
               struct_field,
               struct_field,
               struct_field,
               flatbuffer_field,
               declaration.m_edl_type_info.inner_type->m_name,
               declaration.m_edl_type_info.inner_type->m_name);
        }
        else if (type_kind == FlatbufferSupportedTypes::LinearVectorStructs)
        {
            auto inner_type_name = declaration.m_edl_type_info.inner_type->m_name;
            return FormatString(
                string_to_format,
                flatbuffer_field,
                struct_field,
                struct_field,
                struct_field,
                flatbuffer_field,
                inner_type_name);
        }
        else if (type_kind == FlatbufferSupportedTypes::LinearVectorWString)
        {
            return FormatString(string_to_format, flatbuffer_field, struct_field, struct_field, struct_field, flatbuffer_field);
        }
        else if (type_kind == FlatbufferSupportedTypes::PtrForPrimitive)
        {
            auto statement = FormatString(string_to_format, flatbuffer_field, struct_field);
            return FormatStringForDevTypeToFlatbufferPtr(statement, field_names);
        }
        else if (type_kind == FlatbufferSupportedTypes::PtrForEnum)
        {
            auto statement = FormatString(string_to_format, flatbuffer_field, obj_type, struct_field);
            return FormatStringForDevTypeToFlatbufferPtr(statement, field_names);
        }
        else if (type_kind == FlatbufferSupportedTypes::PtrForStruct)
        {
            auto statement = FormatString(string_to_format, flatbuffer_field, obj_type, struct_field);
            return FormatStringForDevTypeToFlatbufferPtr(statement, field_names);
        }
        else if (type_kind == FlatbufferSupportedTypes::Basic || type_kind == FlatbufferSupportedTypes::WString)
        {
            return FormatString(string_to_format, flatbuffer_field, struct_field);
        }
        else
        {
            // FlatbufferSupportedTypes::NestedStruct and FlatbufferSupportedTypes::Enum
            return FormatString(string_to_format, flatbuffer_field, obj_type, struct_field);
        }
    }

    std::string GetFlatbufferToDevTypeCopyStatements(
        const Declaration& declaration,
        FlatbufferSupportedTypes type_kind,
        FieldNameDataForCopyStatements field_names)
    {
        std::string_view string_to_format = c_flatbuffer_to_dev_type_statement_map.at(type_kind);
        std::string_view obj_type = declaration.m_edl_type_info.m_name;
        std::string_view flatbuffer_field = field_names.m_flatbuffer;
        std::string_view struct_field = field_names.m_struct;

        if (type_kind == FlatbufferSupportedTypes::LinearArrayBasic)
        {
            std::string arr_size = declaration.m_array_dimensions[0];
            return FormatString(
                string_to_format,
                flatbuffer_field,
                flatbuffer_field,
                arr_size,
                flatbuffer_field,
                flatbuffer_field,
                struct_field);
        }
        else if (type_kind == FlatbufferSupportedTypes::LinearArrayStructs)
        {
            auto to_dev_type_func_name = GetToDevTypeFunctionName(declaration);
            std::string arr_size = declaration.m_array_dimensions[0];
            return FormatString(
                string_to_format,
                flatbuffer_field,
                flatbuffer_field,
                arr_size,
                flatbuffer_field,
                flatbuffer_field,
                struct_field,
                obj_type,
                to_dev_type_func_name,
                flatbuffer_field);
        }
        else if (type_kind == FlatbufferSupportedTypes::LinearArrayEnums)
        {
            std::string arr_size = declaration.m_array_dimensions[0];
            return FormatString(
                string_to_format,
                flatbuffer_field,
                flatbuffer_field,
                arr_size,
                flatbuffer_field,
                flatbuffer_field,
                struct_field,
                obj_type,
                obj_type);
        }
        else if (type_kind == FlatbufferSupportedTypes::LinearArrayWString)
        {
            std::string arr_size = declaration.m_array_dimensions[0];
            return FormatString(
                string_to_format,
                flatbuffer_field,
                flatbuffer_field,
                arr_size,
                flatbuffer_field,
                flatbuffer_field,
                struct_field,
                flatbuffer_field);
        }
        else if (type_kind == FlatbufferSupportedTypes::LinearVectorBasic)
        {
            return FormatString(string_to_format, struct_field, flatbuffer_field, flatbuffer_field);
        }
        else if (type_kind == FlatbufferSupportedTypes::LinearVectorEnums)
        {
            return FormatString(
                string_to_format,
                struct_field,
                flatbuffer_field,
                flatbuffer_field,
                flatbuffer_field,
                struct_field,
                declaration.m_edl_type_info.inner_type->m_name,
                declaration.m_edl_type_info.inner_type->m_name);
        }
        else if (type_kind == FlatbufferSupportedTypes::LinearVectorStructs)
        {
            auto to_dev_type_func_name = GetToDevTypeFunctionName(declaration);
            auto inner_type_name = declaration.m_edl_type_info.inner_type->m_name;
            return FormatString(
                string_to_format,
                struct_field,
                flatbuffer_field,
                flatbuffer_field,
                flatbuffer_field,
                struct_field,
                inner_type_name,
                to_dev_type_func_name,
                flatbuffer_field);
        }
        else if (type_kind == FlatbufferSupportedTypes::LinearVectorWString)
        {
            return FormatString(
                string_to_format,
                struct_field,
                flatbuffer_field,
                flatbuffer_field,
                flatbuffer_field,
                struct_field,
                flatbuffer_field);
        }
        else if (type_kind == FlatbufferSupportedTypes::PtrForPrimitive)
        {
            return FormatString(
                string_to_format,
                struct_field,
                obj_type,
                struct_field,
                struct_field,
                flatbuffer_field);
        }
        else if (type_kind == FlatbufferSupportedTypes::PtrForEnum)
        {
            return FormatString(
                string_to_format,
                struct_field,
                obj_type,
                struct_field,
                struct_field,
                obj_type,
                flatbuffer_field);
        }
        else if (type_kind == FlatbufferSupportedTypes::PtrForStruct)
        {
            auto to_dev_type_func_name = GetToDevTypeFunctionName(declaration);
            return FormatString(
                string_to_format,
                flatbuffer_field,
                struct_field,
                obj_type,
                to_dev_type_func_name,
                flatbuffer_field);
        }
        else if (type_kind == FlatbufferSupportedTypes::Basic)
        {
            return FormatString(string_to_format, struct_field, flatbuffer_field);
        }
        else if (type_kind == FlatbufferSupportedTypes::WString)
        {
            return FormatString(string_to_format, flatbuffer_field, struct_field, flatbuffer_field);
        }
        else if (type_kind == FlatbufferSupportedTypes::Enum)
        {
            return FormatString(string_to_format, struct_field, obj_type, flatbuffer_field);
        }
        else if (type_kind == FlatbufferSupportedTypes::NestedStruct)
        {
            auto to_dev_type_func_name = GetToDevTypeFunctionName(declaration);
            return FormatString(string_to_format, flatbuffer_field, struct_field, obj_type, to_dev_type_func_name, flatbuffer_field);
        }
        else
        {
            // FlatbufferSupportedTypes::NestedStruct
            return FormatString(string_to_format, flatbuffer_field, struct_field, obj_type, flatbuffer_field);
        }
    }
}
