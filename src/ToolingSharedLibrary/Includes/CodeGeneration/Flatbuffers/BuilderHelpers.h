// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once 
#include <pch.h>
#include <Edl\Structures.h>
#include <CodeGeneration\CodeGenerationHelpers.h>
#include <sstream>
#include <functional>

using namespace EdlProcessor;

namespace CodeGeneration::Flatbuffers
{
    enum class FlatbufferSupportedTypes : std::uint32_t
    {
        PtrForStruct,
        PtrForEnum,
        PtrForPrimitive,
        Basic,
        WString,
        Enum,
        NestedStruct,
    };

    enum class FlatbufferStructFieldsModifier
    {
        NoModification,
        AbiToFlatbufferSingleStruct,
        AbiToFlatbufferMultipleParameters,
        AbiToDevTypeSingleStruct,
    };

    std::string GenerateFlatbufferSchema(
        const std::vector<DeveloperType>& developer_types_insertion_list,
        const std::vector<DeveloperType>& abi_function_developer_types);


    std::string BuildEnum(const DeveloperType& enum_type);

    std::string BuildTable(const std::vector<Declaration>& fields, std::string_view struct_name);

    std::string GetFlatbufferToDevTypeCopyStatements(
        const Declaration& declaration,
        FlatbufferSupportedTypes type_kind,
        FieldNameDataForCopyStatements variable_names);

    std::string GetDevTypeToFlatbufferCopyStatements(
        const Declaration& declaration,
        FlatbufferSupportedTypes type_kind,
        FieldNameDataForCopyStatements variable_names);

    struct FlatbufferSupportedTypesHash
    {
        std::size_t operator()(FlatbufferSupportedTypes type) const
        {
            return std::hash<std::uint32_t>()(static_cast<std::uint32_t>(type));
        }
    };

    static const std::unordered_map<FlatbufferSupportedTypes, std::string_view, FlatbufferSupportedTypesHash> c_flatbuffer_to_dev_type_statement_map =
    {
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
        { FlatbufferSupportedTypes::PtrForPrimitive, c_dev_type_to_flatbuffer_conversion_ptr_for_primitive },
        { FlatbufferSupportedTypes::PtrForEnum, c_dev_type_to_flatbuffer_conversion_ptr_for_enum },
        { FlatbufferSupportedTypes::PtrForStruct, c_dev_type_to_flatbuffer_conversion_ptr_for_struct },
        { FlatbufferSupportedTypes::Basic, c_dev_type_to_flatbuffer_conversion_basic },
        { FlatbufferSupportedTypes::WString, c_dev_type_to_flatbuffer_conversion_wstring },
        { FlatbufferSupportedTypes::Enum, c_dev_type_to_flatbuffer_conversion_enum },
        { FlatbufferSupportedTypes::NestedStruct, c_dev_type_to_flatbuffer_conversion_nestedstruct },
    };
}

}
