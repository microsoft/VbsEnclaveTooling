// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once 
#include <pch.h>
#include <Edl\Structures.h>
#include <CodeGeneration\CodeGeneration.h>
#include <CodeGeneration\Contants.h>
#include <ErrorHelpers.h>

using namespace EdlProcessor;
using namespace ErrorHelpers;

namespace CodeGeneration
{
    CppCodeGenerator::CppCodeGenerator(const Edl& edl, const CmdlineArgumentsParser& parser)
        :   m_edl(edl), m_output_folder_path(parser.OutDirectory()), m_error_handling(parser.ErrorHandling())
    {
    }

    void CppCodeGenerator::Generate()
    {
        m_base_header = m_builder.BuildBaseHeaderFile();
        m_enclave_types_header = GenerateDeveloperTypesHeader();


        // Save the base header for enclave functionality to output location
        SaveFileToOutputFolder(
            c_base_header_name_with_ext,
            m_output_folder_path,
            m_base_header);

        // Save the developer types to a header file in the output location
        SaveFileToOutputFolder(
            c_developer_types_header,
            m_output_folder_path,
            m_enclave_types_header);
    }

    std::string CppCodeGenerator::GenerateDeveloperTypesHeader()
    {
        std::string types_header {};

        for (auto&& [name, type] : m_edl.m_developer_types)
        {
            if (type->m_type_kind == EdlTypeKind::Enum ||
                type->m_type_kind == EdlTypeKind::AnonymousEnum)
            {
                types_header += m_builder.BuildEnumDefinition(type);
            }
            else
            {
                types_header += m_builder.BuildStructDefinition(type);
            }
        }

        return m_builder.BuildDeveloperTypesHeaderFile(types_header);
    }

    void CppCodeGenerator::SaveFileToOutputFolder(
        const std::string_view& file_name,
        const std::filesystem::path& output_folder,
        const std::string_view& file_content)
    {
        auto output_file_path = output_folder / file_name;
        std::ofstream output_file(output_file_path.generic_string());

        if (output_file.is_open())
        {
            output_file << file_content;
            output_file.close();
        }
        else
        {
            throw CodeGenerationException(
                ErrorId::CodeGenUnableToOpenOutputFile,
                output_file_path.generic_string());
        }
    }
}
