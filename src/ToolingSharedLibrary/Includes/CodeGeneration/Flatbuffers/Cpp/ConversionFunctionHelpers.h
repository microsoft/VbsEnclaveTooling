// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once 
#include <pch.h>
#include <Edl\Structures.h>
#include <Edl\Utils.h>
#include <CodeGeneration\Contants.h>
#include <CodeGeneration\CodeGeneration.h>
#include <CodeGeneration\Flatbuffers\Cpp\CppContants.h>
#include <CodeGeneration\Flatbuffers\BuilderHelpers.h>

#include <sstream>

using namespace EdlProcessor;

namespace CodeGeneration::Flatbuffers::Cpp
{
    struct FieldNameDataForCopyStatements
    {
        std::string m_flatbuffer {};
        std::string m_struct {};
        FlatbufferStructFieldsModifier m_modifier = FlatbufferStructFieldsModifier::NoModification;
    };

    std::string BuildConversionFunctionBody(
        const std::vector<Declaration>& fields,
        FlatbufferConversionKind conversion_kind,
        FlatbufferStructFieldsModifier modifier = FlatbufferStructFieldsModifier::NoModification);

    std::string FormatStringForDevTypeToFlatbufferPtr(
        std::string_view last_part,
        const FieldNameDataForCopyStatements& field_names);

    std::string GetDevTypeToFlatbufferCopyStatements(
        const Declaration& declaration,
        FlatbufferSupportedTypes type_kind,
        FieldNameDataForCopyStatements field_names);

    std::string GetFlatbufferToDevTypeCopyStatements(
        const Declaration& declaration,
        FlatbufferSupportedTypes type_kind,
        FieldNameDataForCopyStatements field_names);


    struct FlatbufferSupportedTypesHash
    {
        std::size_t operator()(FlatbufferSupportedTypes type) const
        {
            return std::hash<std::uint32_t>()(static_cast<std::uint32_t>(type));
        }
    };

    static const std::unordered_map<FlatbufferSupportedTypes, std::string_view, FlatbufferSupportedTypesHash> c_flatbuffer_to_dev_type_statement_map =
    {
        { FlatbufferSupportedTypes::LinearArrayBasic, c_flatbuffer_to_dev_type_conversion_linear_array_basic },
        { FlatbufferSupportedTypes::LinearArrayStructs, c_flatbuffer_to_dev_type_conversion_linear_array_structs },
        { FlatbufferSupportedTypes::LinearArrayEnums, c_flatbuffer_to_dev_type_conversion_linear_array_enums },
        { FlatbufferSupportedTypes::LinearArrayWString, c_flatbuffer_to_dev_type_conversion_linear_array_wstring },
        { FlatbufferSupportedTypes::LinearVectorBasic, c_flatbuffer_to_dev_type_conversion_linear_vector_basic },
        { FlatbufferSupportedTypes::LinearVectorEnums, c_flatbuffer_to_dev_type_conversion_linear_vector_enums },
        { FlatbufferSupportedTypes::LinearVectorStructs, c_flatbuffer_to_dev_type_conversion_linear_vector_structs },
        { FlatbufferSupportedTypes::LinearVectorWString, c_flatbuffer_to_dev_type_conversion_linear_vector_wstring },
        { FlatbufferSupportedTypes::PtrForPrimitive, c_flatbuffer_to_dev_type_conversion_ptr_for_primitive },
        { FlatbufferSupportedTypes::PtrForEnum, c_flatbuffer_to_dev_type_conversion_ptr_for_enum },
        { FlatbufferSupportedTypes::PtrForStruct, c_flatbuffer_to_dev_type_conversion_ptr_for_struct },
        { FlatbufferSupportedTypes::Basic, c_flatbuffer_to_dev_type_conversion_basic },
        { FlatbufferSupportedTypes::WString, c_flatbuffer_to_dev_type_conversion_wstring },
        { FlatbufferSupportedTypes::Enum, c_flatbuffer_to_dev_type_conversion_enum },
        { FlatbufferSupportedTypes::NestedStruct, c_flatbuffer_to_dev_type_conversion_nestedstruct },
    };

    static const std::unordered_map<FlatbufferSupportedTypes, std::string_view, FlatbufferSupportedTypesHash> c_dev_type_to_flatbuffer_statement_map =
    {
        { FlatbufferSupportedTypes::LinearArrayBasic, c_dev_type_to_flatbuffer_conversion_linear_array_basic },
        { FlatbufferSupportedTypes::LinearArrayStructs, c_dev_type_to_flatbuffer_conversion_linear_array_structs },
        { FlatbufferSupportedTypes::LinearArrayEnums, c_dev_type_to_flatbuffer_conversion_linear_array_enums },
        { FlatbufferSupportedTypes::LinearArrayWString, c_dev_type_to_flatbuffer_conversion_linear_array_wstrings },
        { FlatbufferSupportedTypes::LinearVectorBasic, c_dev_type_to_flatbuffer_conversion_linear_vector_basic },
        { FlatbufferSupportedTypes::LinearVectorEnums, c_dev_type_to_flatbuffer_conversion_linear_vector_enums },
        { FlatbufferSupportedTypes::LinearVectorStructs, c_dev_type_to_flatbuffer_conversion_linear_vector_structs },
        { FlatbufferSupportedTypes::LinearVectorWString, c_dev_type_to_flatbuffer_conversion_linear_vector_wstrings },
        { FlatbufferSupportedTypes::PtrForPrimitive, c_dev_type_to_flatbuffer_conversion_ptr_for_primitive },
        { FlatbufferSupportedTypes::PtrForEnum, c_dev_type_to_flatbuffer_conversion_ptr_for_enum },
        { FlatbufferSupportedTypes::PtrForStruct, c_dev_type_to_flatbuffer_conversion_ptr_for_struct },
        { FlatbufferSupportedTypes::Basic, c_dev_type_to_flatbuffer_conversion_basic },
        { FlatbufferSupportedTypes::WString, c_dev_type_to_flatbuffer_conversion_wstring },
        { FlatbufferSupportedTypes::Enum, c_dev_type_to_flatbuffer_conversion_enum },
        { FlatbufferSupportedTypes::NestedStruct, c_dev_type_to_flatbuffer_conversion_nestedstruct },
    };
}
