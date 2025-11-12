// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once 
#include <pch.h>
#include <Edl\Structures.h>
#include <CmdlineParsingHelpers.h>
#include <CmdlineArgumentsParser.h>
#include "CodeGenerationHelpers.h"
#include <Utils\Helpers.h>
#include <CodeGeneration/Common/Types.h>

using namespace CmdlineParsingHelpers;
using namespace EdlProcessor;

namespace CodeGeneration::Rust
{
    namespace CodeBuilder
    {
        std::string GenerateDeveloperTypesModuleFile(
            std::string_view developer_namespace_name,
            const OrderedMap<std::string, DeveloperType>& developer_types_map);

        std::string GenerateAbiTypesModuleFile(
            std::string_view developer_namespace_name,
            std::span<const DeveloperType> abi_function_developer_types);

        std::string GenerateFlatbuffersPackModuleFile(
            std::string_view developer_namespace_name,
            std::span<const DeveloperType> abi_function_developer_types);

        Definition BuildStartOfDefinition(
            std::string_view type_name,
            std::string_view identifier_name,
            std::size_t num_of_tabs = 0U);

        std::string BuildEnumDefinition(
            std::string_view developer_namespace_name,
            const DeveloperType& developer_types);

        std::string BuildStructField(const Declaration& declaration);

        std::string BuildStructDefinition(
            std::string_view struct_name,
            std::string_view developer_namespace_name,
            const std::vector<Declaration>& fields);
    };

    struct RustCodeGenerator : public CodeGeneratorBase
    {
    public:
        using CodeGeneratorBase::CodeGeneratorBase;

        void Generate() override;
    };
}
