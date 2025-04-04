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

    std::string GenerateFlatbufferSchema(
        const std::vector<DeveloperType>& developer_types_insertion_list,
        const std::vector<DeveloperType>& abi_function_developer_types);

    std::string BuildEnum(const DeveloperType& enum_type);

    std::string BuildTable(const std::vector<Declaration>& fields, std::string_view struct_name);
}
