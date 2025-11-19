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
            VirtualTrustLayerKind vtl_kind,
            const OrderedMap<std::string, DeveloperType>& developer_types_map);

        std::string GenerateAbiTypesModuleFile(
            std::string_view developer_namespace_name,
            VirtualTrustLayerKind vtl_kind,
            std::span<const DeveloperType> abi_function_developer_types);

        std::string GenerateFlatbuffersWrapperModuleFile(
            std::string_view developer_namespace_name,
            VirtualTrustLayerKind vtl_kind,
            std::span<const DeveloperType> abi_function_developer_types);

        Definition BuildStartOfDefinition(
            std::string_view type_name,
            std::string_view identifier_name,
            std::size_t num_of_tabs = 0U);

        std::string BuildEnumDefinition(
            const DeveloperType& developer_types);

        std::string BuildStructDefinition(
            std::string_view struct_name,
            const std::vector<Declaration>& fields);

        std::string BuildImplTraitModule(
            VirtualTrustLayerKind vtl_kind,
            const OrderedMap<std::string, Function>& functions);

        std::string BuildStubTraitModule(
            VirtualTrustLayerKind vtl_kind,
            std::string_view stub_class_name,
            std::string_view developer_namespace_name,
            const OrderedMap<std::string, Function>& functions);

        std::string BuildAbiDefinitionModule(
            VirtualTrustLayerKind vtl_kind,
            std::string_view developer_namespace_name,
            const OrderedMap<std::string, Function>& functions);
    };

    struct RustCodeGenerator : public CodeGeneratorBase
    {
    public:
        using CodeGeneratorBase::CodeGeneratorBase;

        void Generate() override;

    private:

        void GenerateImplementationModules(
            const std::filesystem::path& implementation_location);

        void GenerateAbiModules(
            const std::filesystem::path& src_location,
            const std::filesystem::path& abi_location);

        void GenerateFlatbufferComponents(
            const std::vector<DeveloperType>& abi_function_developer_types,
            const std::filesystem::path& abi_location);

        void GenerateStubModules(
            const std::filesystem::path& stub_location);

        void GenerateAbiBoundaryModule(
            const std::filesystem::path& abi_location);
    };
}
