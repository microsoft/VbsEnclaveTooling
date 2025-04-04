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
        LinearArrayBasic,
        LinearArrayEnums,
        LinearArrayStructs,
        LinearArrayWString,
        LinearVectorBasic,
        LinearVectorEnums,
        LinearVectorStructs,
        LinearVectorWString,
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

    enum class FlatbufferConversionKind : std::uint32_t
    {
        ToDevType,
        ToFlatbuffer,
    };

    std::string GenerateFlatbufferSchema(
        const std::vector<DeveloperType>& developer_types_insertion_list,
        const std::vector<DeveloperType>& abi_function_developer_types);

    std::string BuildEnum(const DeveloperType& enum_type);

    std::string BuildTable(const std::vector<Declaration>& fields, std::string_view struct_name);

    inline FlatbufferSupportedTypes GetSupportedFlatbufferTypeKindForVector(const Declaration& declaration)
    {
        auto inner_type = declaration.m_edl_type_info.inner_type;

        if (inner_type && inner_type->m_type_kind == EdlTypeKind::Enum)
        {
            return FlatbufferSupportedTypes::LinearVectorEnums;
        }
        else if (inner_type && inner_type->m_type_kind == EdlTypeKind::Struct)
        {
            return FlatbufferSupportedTypes::LinearVectorStructs;
        }
        else if (inner_type && inner_type->m_type_kind == EdlTypeKind::WString)
        {
            return FlatbufferSupportedTypes::LinearVectorWString;
        }

        return FlatbufferSupportedTypes::LinearVectorBasic;
    }

    // TODO: Make static map
    inline FlatbufferSupportedTypes GetSupportedFlatbufferTypeKind(const Declaration& declaration)
    {
        auto& type_info = declaration.m_edl_type_info;

        // These are the types we support. Just like the WString case we can always
        // create a custom type using the natively supported types of flatbuffers
        // should we ever need to expand this.
        switch (type_info.m_type_kind)
        {
            case EdlTypeKind::Bool:
            case EdlTypeKind::Char:
            case EdlTypeKind::Int8:
            case EdlTypeKind::WChar:
            case EdlTypeKind::Int16:
            case EdlTypeKind::HRESULT:
            case EdlTypeKind::Int32:
            case EdlTypeKind::Int64:
            case EdlTypeKind::Float:
            case EdlTypeKind::Double:
            case EdlTypeKind::UInt8:
            case EdlTypeKind::UInt16:
            case EdlTypeKind::UInt32:
            case EdlTypeKind::SizeT:
            case EdlTypeKind::UInt64:
            case EdlTypeKind::UIntPtr:
            case EdlTypeKind::String:
                return FlatbufferSupportedTypes::Basic;
            case EdlTypeKind::WString:
                return FlatbufferSupportedTypes::WString;
            case EdlTypeKind::Enum:
                return FlatbufferSupportedTypes::Enum;
            case EdlTypeKind::Struct:
                return FlatbufferSupportedTypes::NestedStruct;
            case EdlTypeKind::Vector:
                return GetSupportedFlatbufferTypeKindForVector(declaration);
            default:
                throw CodeGenerationException(
                    ErrorId::FlatbufferTypeNotCompatibleWithEdlType,
                    type_info.m_name,
                    declaration.m_name);
        }
    }
}
