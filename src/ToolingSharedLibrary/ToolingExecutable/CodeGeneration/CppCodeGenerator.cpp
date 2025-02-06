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
using namespace CodeGeneration::CppCodeBuilder;

namespace CodeGeneration
{
    CppCodeGenerator::CppCodeGenerator(
        const Edl& edl,
        const std::filesystem::path& output_path,
        ErrorHandlingKind error_handling)
        :   m_edl(edl), m_output_folder_path(output_path), m_error_handling(error_handling)
    {
    }

    void CppCodeGenerator::Generate()
    {
        std::string enclave_headers_output = std::format(c_output_folder_for_generated_trusted_functions, m_edl.m_name);
        std::string hostapp_headers_output = std::format(c_output_folder_for_generated_untrusted_functions, m_edl.m_name);

        auto enclave_types_header = BuildDeveloperTypesHeader(m_edl.m_developer_types);

        // Save the developer types to a header file in the output location
        SaveFileToOutputFolder(
            c_developer_types_header,
            m_output_folder_path / c_output_folder_for_shared_files,
            enclave_types_header);

        if (!m_edl.m_trusted_functions.empty())
        {
            auto enclave_headers = BuildHostToEnclaveFunctions(m_edl.m_name, m_edl.m_trusted_functions);

            SaveFileToOutputFolder(
                c_untrusted_vtl0_stubs_header,
                m_output_folder_path / hostapp_headers_output,
                enclave_headers.vtl0_class_header_content);

            auto trusted_location = m_output_folder_path / enclave_headers_output;

            SaveFileToOutputFolder(
                c_trust_vtl1_stubs_header,
                trusted_location,
                enclave_headers.vtl1_stub_functions_header_content);

            SaveFileToOutputFolder(
                c_trusted_vtl1_impl_header,
                trusted_location,
                enclave_headers.vtl1_developer_impls_header_content);

            SaveFileToOutputFolder(
                c_output_module_def_file_name,
                trusted_location,
                enclave_headers.vtl1_enclave_module_defintiion_content);

            SaveFileToOutputFolder(
                c_parameter_verifier_header,
                trusted_location,
                enclave_headers.vtl1_verifiers_header_content);
        }
    }

    void CppCodeGenerator::SaveFileToOutputFolder(
        std::string_view file_name,
        const std::filesystem::path& output_folder,
        std::string_view file_content)
    {
        auto output_file_path = output_folder / file_name;

        if (!std::filesystem::exists(output_folder) && !std::filesystem::create_directories(output_folder))
        {
            throw CodeGenerationException(
                ErrorId::CodeGenUnableToOpenOutputFile,
                output_file_path.generic_string());
            
        }

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
