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
        Basic,
        WString,
        Enum,
        NestedStruct,
    };

    struct FlatbufferDataForFunction
    {
        std::ostringstream m_flatbuffer_tables{};
        std::ostringstream m_parameters_struct{};
    };

    std::ostringstream BuildInitialFlatbufferSchemaContent(
        const std::vector<DeveloperType>& developer_types_insertion_list);

    std::string BuildEnum(const DeveloperType& enum_type);

    std::string BuildTable(const std::vector<Declaration>& fields, std::string_view struct_name);


    FlatbufferDataForFunction BuildFlatbufferConversionStructsAndTables(
        Function function,
        std::string_view abi_function_name,
        const CppCodeBuilder::FunctionParametersInfo& params_info);
}
