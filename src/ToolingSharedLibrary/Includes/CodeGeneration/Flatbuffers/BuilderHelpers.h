// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once 
#include <pch.h>
#include <Edl\Structures.h>

using namespace EdlProcessor;

namespace CodeGeneration::Flatbuffers
{
    std::string GenerateFlatbufferSchema(
        std::string_view developer_namespace_name,
        const std::vector<DeveloperType>& developer_types_insertion_list,
        const std::vector<DeveloperType>& abi_function_developer_types);

    std::string BuildEnum(const DeveloperType& enum_type);

    std::string BuildTable(const std::vector<Declaration>& fields, std::string_view struct_name);
}
