// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once 
#include <pch.h>
#include <Edl\Structures.h>
#include <CmdlineParsingHelpers.h>
#include <CmdlineArgumentsParser.h>
#include "CodeGenerationHelpers.h"

using namespace CmdlineParsingHelpers;
using namespace EdlProcessor;

namespace CodeGeneration
{

    namespace CppCodeBuilder
    {
        std::string BuildBaseHeaderFile();

        std::string BuildDeveloperTypesHeaderFile(std::string_view header_content);

        std::string EncapsulateCodeInNamespace(
            std::string_view namespace_name,
            std::string_view code);

        std::tuple<std::string, std::string, std::string> BuildStartOfDefinition(
            std::string_view type_name,
            std::string_view identifier_name);

        std::string AddUsingNamespace(std::string_view namespace_name);

        std::string BuildEnumDefinition(const DeveloperType& developer_types);

        std::string GetTypeInfo(const EdlTypeInfo& info);

        std::string BuildStructField(const Declaration& declaration);

        std::string BuildStructDefinition(const DeveloperType& developer_types);

        std::string BuildStdArrayType(
            std::string_view type,
            const ArrayDimensions& dimensions,
            std::uint32_t index = 0);

        std::string BuildNonArrayType(const Declaration& declaration);
    };

    struct CppCodeGenerator
    {
        CppCodeGenerator(
            const Edl& edl,
            const std::filesystem::path& output_path,
            ErrorHandlingKind error_handling);

        void Generate();

    private:
        std::string GenerateDeveloperTypesHeader();

        void SaveFileToOutputFolder(
            std::string_view file_name,
            const std::filesystem::path& output_folder,
            std::string_view file_content);

        Edl m_edl {};
        ErrorHandlingKind m_error_handling {};
        std::filesystem::path m_output_folder_path {};
    };
}
