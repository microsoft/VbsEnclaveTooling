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

struct CppCodeBuilder
{
    std::string BuildBaseHeaderFile();

    std::string BuildDeveloperTypesHeaderFile(const std::string& header_content);

    std::string EncapsulateCodeInNamespace(
        const std::string_view& namespace_name,
        const std::string_view& code);

    std::tuple<std::string, std::string, std::string> BuildStartOfDefinition(
        const std::string_view& type_name,
        const std::string_view& identifier_name);

    std::string AddUsingNamespace(const std::string_view& namespace_name);

    std::string BuildEnumDefinition(const std::shared_ptr<DeveloperType>& developer_types);

    std::string GetTypeInfo(const std::shared_ptr<EdlTypeInfo>& info);

    std::string BuildStructField(const Declaration& declaration);

    std::string BuildStructDefinition(const std::shared_ptr<DeveloperType>& developer_types);

    std::string BuildStdArrayType(
        const std::string_view& type,
        const ArrayDimensions& dimensions,
        const std::uint32_t& index = 0);

    std::string BuildNonArrayType(const Declaration& declaration);
};

struct CppCodeGenerator
{
    CppCodeGenerator(const Edl& edl, const CmdlineArgumentsParser& parser);

    void Generate();

    std::string_view EnclaveTypesHeader() { return m_enclave_types_header; }
    std::string_view EnclaveBaseHeader() { return m_base_header; }

private:
    std::string GenerateDeveloperTypesHeader();

    void SaveFileToOutputFolder(
        const std::string_view& file_name,
        const std::filesystem::path& output_folder,
        const std::string_view& file_content);

    Edl m_edl {};
    CppCodeBuilder m_builder {};
    ErrorHandlingKind m_error_handling {};
    std::filesystem::path m_output_folder_path {};
    std::string m_base_header {};
    std::string m_enclave_types_header {};
};
}
