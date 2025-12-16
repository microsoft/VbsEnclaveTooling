// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once 
#include <pch.h>
#include <CodeGeneration\Cpp\CodeGeneration.h>
#include <CodeGeneration\Cpp\Constants.h>
#include <CodeGeneration\Flatbuffers\Constants.h>
#include <CodeGeneration\Flatbuffers\BuilderHelpers.h>
#include <Edl\Structures.h>
#include <ErrorHelpers.h>

using namespace EdlProcessor;
using namespace ErrorHelpers;
using namespace CodeGeneration::Cpp::CppCodeBuilder;
using namespace CodeGeneration::Flatbuffers;

namespace CodeGeneration::Cpp
{
    void CppCodeGenerator::Generate()
    {
        using namespace CppCodeBuilder;

        std::string enclave_headers_output = std::format(c_output_folder_for_generated_trusted_functions, m_edl.m_name);
        std::string hostapp_headers_output = std::format(c_output_folder_for_generated_untrusted_functions, m_edl.m_name);
        auto enclave_headers_location = m_output_folder_path / enclave_headers_output;
        auto hostapp_headers_location = m_output_folder_path / hostapp_headers_output;

        // Use OrderedMap directly
        auto abi_function_developer_types = CreateDeveloperTypesForABIFunctions(
            m_edl.m_trusted_functions,
            m_edl.m_untrusted_functions);

        // Create developer types. This is shared between
        // the HostApp and the enclave.
        std::string enclave_types_header = BuildDeveloperTypesHeader(
            m_generated_namespace_name,
            m_edl.m_developer_types);

        auto flatbuffer_schema = GenerateFlatbufferSchema(
            m_generated_namespace_name,
            m_edl.m_developer_types,
            abi_function_developer_types);

        // Process content from the trusted content.
        auto host_to_enclave_content = BuildHostToEnclaveFunctions(
            m_generated_namespace_name,
            m_edl.m_trusted_functions);

        // Process the content from the untrusted functions
        auto enclave_to_host_content = BuildEnclaveToHostFunctions(
            m_generated_namespace_name, 
            m_edl.m_untrusted_functions);

        std::filesystem::path save_location{};
        HeaderKind header_kind{};

        if (m_virtual_trust_layer_kind == VirtualTrustLayerKind::Enclave)
        {
            save_location = enclave_headers_location;
            header_kind = HeaderKind::Vtl1;

            std::string exported_definitions_source = BuildVtl1ExportedFunctionsSourcefile(
                m_generated_namespace_name,
                m_edl.m_trusted_functions);

            SaveFileToOutputFolder(
                std::format(c_enclave_exports_source, m_edl.m_name),
                save_location / "Abi",
                exported_definitions_source);

            std::string pragma_statements = BuildVtl1PragmaStatementsSourcefile(
                m_generated_namespace_name,
                m_edl.m_trusted_functions);

            SaveFileToOutputFolder(
                std::format(c_enclave_linker_statements_file, m_edl.m_name),
                save_location / "Abi",
                pragma_statements);
        }
        else if (m_virtual_trust_layer_kind == VirtualTrustLayerKind::HostApp)
        {
            save_location = hostapp_headers_location;
            header_kind = HeaderKind::Vtl0;
        }
        else
        {
            throw CodeGenerationException(ErrorId::VirtualTrustLayerInvalidType);
        }

        std::string developer_types_header = BuildDeveloperTypesHeader(
            m_generated_namespace_name,
            m_edl.m_developer_types);

        SaveFileToOutputFolder(c_types_header_name, save_location / "Implementation", developer_types_header);
        SaveTrustedHeader(header_kind, save_location, host_to_enclave_content, enclave_to_host_content);
        SaveUntrustedHeader(header_kind, save_location, enclave_to_host_content);
        
        auto abi_save_location = save_location / "Abi";
        SaveAbiDefinitionsHeader(header_kind, abi_save_location, host_to_enclave_content, enclave_to_host_content);

        auto sub_folder_name = (header_kind == HeaderKind::Vtl0) ? "HostApp" : "Enclave";
        std::string abi_function_types_header = BuildAbiTypesHeader(
            m_generated_namespace_name,
            sub_folder_name,
            abi_function_developer_types);

        SaveFileToOutputFolder("AbiTypes.h", abi_save_location, abi_function_types_header);

        std::string abi_metadata_types_header = BuildAbiTypesMetadataHeader(
            m_generated_namespace_name,
            sub_folder_name,
            m_edl.m_developer_types,
            abi_function_developer_types);

        SaveFileToOutputFolder("TypeMetadata.h", abi_save_location, abi_metadata_types_header);

        SaveFileToOutputFolder(c_flatbuffer_fbs_filename, abi_save_location, flatbuffer_schema);
        SaveFileToOutputFolder(c_abi_flatbuffers_file_name, abi_save_location, c_abi_flatbuffers_content);
        CompileFlatbufferFile(m_flatbuffer_compiler_path,c_cpp_gen_args, abi_save_location);
    }

    void CppCodeGenerator::SaveTrustedHeader(
        CppCodeBuilder::HeaderKind header_kind,
        const std::filesystem::path& output_parent_folder,
        const CppCodeBuilder::HostToEnclaveContent& host_to_enclave_content,
        const CppCodeBuilder::EnclaveToHostContent& enclave_to_host_content)
    {
        std::string header_content{};
        std::filesystem::path output_subfolder{};

        if (header_kind == HeaderKind::Vtl1)
        {
            header_content = std::format(
                c_vtl1_trusted_func_declarations_header,
                c_autogen_header_string,
                m_generated_namespace_name,
                m_generated_namespace_name,
                host_to_enclave_content.m_vtl1_trusted_function_declarations);
            output_subfolder = output_parent_folder / "Implementation";
        }
        else
        {
            std::string callbacks_name = std::format(
                c_vtl1_register_callbacks_abi_export_name,
                m_generated_namespace_name);

            std::string callbacks_name_with_quotes = std::format("\"{}\"", callbacks_name);

            std::string vtl0_register_callbacks_abi_function = std::format(
                c_vtl0_register_callbacks_abi_function,
                callbacks_name_with_quotes);

            auto public_content = std::format("{}{}",
                host_to_enclave_content.m_vtl0_trusted_stub_functions,
                vtl0_register_callbacks_abi_function);

            header_content = std::format(
                c_vtl0_trusted_header,
                c_autogen_header_string,
                m_generated_namespace_name,
                m_generated_namespace_name,
                m_generated_vtl0_class_name,
                m_generated_vtl0_class_name,
                public_content,
                enclave_to_host_content.m_vtl0_untrusted_abi_stubs_address_info);

            output_subfolder = output_parent_folder / "Stubs";
        }

        SaveFileToOutputFolder("Trusted.h", output_subfolder, header_content);
    }

    void CppCodeGenerator::SaveUntrustedHeader(
        CppCodeBuilder::HeaderKind header_kind,
        const std::filesystem::path& output_parent_folder,
        const CppCodeBuilder::EnclaveToHostContent& enclave_to_host_content)
    {
        std::string header_template{};
        std::string sub_namespace_content{};
        std::filesystem::path output_subfolder {};

        if (header_kind == HeaderKind::Vtl1)
        {
            header_template = c_vtl1_untrusted_stubs_header_template;
            sub_namespace_content = enclave_to_host_content.m_vtl1_stubs_for_vtl0_untrusted_functions;
            output_subfolder = output_parent_folder / "Stubs";
        }
        else
        {
            header_template = c_vtl0_untrusted_impl_header_template;
            sub_namespace_content = enclave_to_host_content.m_vtl0_untrusted_function_declarations;
            output_subfolder = output_parent_folder / "Implementation";
        }

        std::string header_content = FormatString(
            header_template,
            c_autogen_header_string,
            m_generated_namespace_name,
            m_generated_namespace_name,
            sub_namespace_content);

        SaveFileToOutputFolder("Untrusted.h", output_subfolder, header_content);
    }

    void CppCodeGenerator::SaveAbiDefinitionsHeader(
        CppCodeBuilder::HeaderKind header_kind,
        const std::filesystem::path& output_parent_folder,
        const CppCodeBuilder::HostToEnclaveContent& host_to_enclave_content,
        const CppCodeBuilder::EnclaveToHostContent& enclave_to_host_content)
    {
        std::string definitions_namespace_content {};
        std::string runtime_namespace_content {};
        std::string includes {};

        if (header_kind == HeaderKind::Vtl1)
        {
            runtime_namespace_content = c_vtl1_enforce_mem_restriction_func;
            definitions_namespace_content = host_to_enclave_content.m_vtl1_abi_functions;
            includes = c_vtl1_abi_definitions_includes;
        }
        else
        {
            definitions_namespace_content = enclave_to_host_content.m_vtl0_abi_functions;
            includes = c_vtl0_abi_definitions_includes;
        }

        std::string header_content = std::format(
            c_abi_definitions_stubs_header_template,
            c_autogen_header_string,
            includes,
            m_generated_namespace_name,
            runtime_namespace_content,
            definitions_namespace_content);

        SaveFileToOutputFolder("Definitions.h", output_parent_folder, header_content);
    }
}
