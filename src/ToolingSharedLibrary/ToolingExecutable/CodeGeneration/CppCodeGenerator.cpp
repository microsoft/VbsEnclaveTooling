// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once 
#include <pch.h>
#include <Edl\Structures.h>
#include <CodeGeneration\CodeGeneration.h>
#include <CodeGeneration\Contants.h>
#include <ErrorHelpers.h>
#include <CodeGeneration\Flatbuffers\Contants.h>
#include <CodeGeneration\Flatbuffers\BuilderHelpers.h>

using namespace EdlProcessor;
using namespace ErrorHelpers;
using namespace CodeGeneration::CppCodeBuilder;
using namespace CodeGeneration::Flatbuffers;
namespace CodeGeneration
{
    CppCodeGenerator::CppCodeGenerator(
        const Edl& edl,
        const std::filesystem::path& output_path,
        ErrorHandlingKind error_handling,
        VirtualTrustLayerKind trust_layer,
        std::string_view generated_namespace_name,
        std::string_view generated_vtl0_class_name,
        std::string_view flatbuffer_compiler_path)
        :   m_edl(edl),
            m_output_folder_path(output_path),
            m_error_handling(error_handling),
            m_virtual_trust_layer_kind(trust_layer),
            m_generated_namespace_name(generated_namespace_name),
            m_generated_vtl0_class_name(generated_vtl0_class_name),
            m_flatbuffer_compiler_path(flatbuffer_compiler_path)
    {
        if (m_output_folder_path.empty())
        {
            // Make output directory current directory by default if not provided.
            m_output_folder_path = std::filesystem::current_path();
        }

        if (m_generated_namespace_name.empty())
        {
            m_generated_namespace_name = edl.m_name;
        }

        if (m_generated_vtl0_class_name.empty())
        {
            m_generated_vtl0_class_name = std::move(std::format(c_vtl0_enclave_class_name, edl.m_name));
        }

        if (m_flatbuffer_compiler_path.empty())
        {
            // Set flatbuffer compiler path to current directory by default if not provided.
            m_flatbuffer_compiler_path = std::format(
                c_flatbuffer_compiler_default_path,
                std::filesystem::current_path().generic_string());
        }
    }

    void CppCodeGenerator::Generate()
    {
        std::string enclave_headers_output = std::format(c_output_folder_for_generated_trusted_functions, m_edl.m_name);
        std::string hostapp_headers_output = std::format(c_output_folder_for_generated_untrusted_functions, m_edl.m_name);
        auto enclave_headers_location = m_output_folder_path / enclave_headers_output;
        auto hostapp_headers_location = m_output_folder_path / hostapp_headers_output;

        auto abi_function_developer_types = CreateDeveloperTypesForABIFunctions(
            m_edl.m_trusted_functions_list,
            m_edl.m_untrusted_functions_list);

        // Create developer types. This is shared between
        // the HostApp and the enclave.
        std::string enclave_types_header = BuildTypesHeader(
            m_generated_namespace_name,
            m_edl.m_developer_types_insertion_order_list,
            abi_function_developer_types);

        auto flatbuffer_schema = GenerateFlatbufferSchema(
            m_generated_namespace_name,
            m_edl.m_developer_types_insertion_order_list,
            abi_function_developer_types);

        // Process content from the trusted content.
        auto host_to_enclave_content = BuildHostToEnclaveFunctions(
            m_generated_namespace_name,
            m_edl.m_developer_types,
            m_edl.m_trusted_functions_list);

        // Process the content from the untrusted functions
        auto enclave_to_host_content = BuildEnclaveToHostFunctions(
            m_generated_namespace_name, 
            m_generated_vtl0_class_name,
            m_edl.m_developer_types,
            m_edl.m_untrusted_functions_list);

        std::filesystem::path save_location{};
        CppCodeBuilder::HeaderKind header_kind{};

        if (m_virtual_trust_layer_kind == VirtualTrustLayerKind::Enclave)
        {
            save_location = enclave_headers_location;
            header_kind = CppCodeBuilder::HeaderKind::Vtl1;

            std::string exported_definitions_source = BuildVtl1ExportedFunctionsSourcefile(
                m_generated_namespace_name,
                m_edl.m_trusted_functions_list);

            SaveFileToOutputFolder(
                c_enclave_exports_source,
                save_location,
                exported_definitions_source);
        }
        else if (m_virtual_trust_layer_kind == VirtualTrustLayerKind::HostApp)
        {
            save_location = hostapp_headers_location;
            header_kind = CppCodeBuilder::HeaderKind::Vtl0;
        }
        else
        {
            throw CodeGenerationException(ErrorId::VirtualTrustLayerInvalidType);
        }

        SaveTrustedHeader(header_kind, save_location, host_to_enclave_content, enclave_to_host_content);
        SaveUntrustedHeader(header_kind, save_location, enclave_to_host_content);
        SaveAbiDefinitionsHeader(header_kind, save_location, host_to_enclave_content, enclave_to_host_content);

        SaveFileToOutputFolder(c_flatbuffer_fbs_filename, save_location, flatbuffer_schema);
        CompileFlatbufferFile(save_location);
        SaveFileToOutputFolder(c_developer_types_header, save_location, enclave_types_header);
    }

    void CppCodeGenerator::SaveTrustedHeader(
        CppCodeBuilder::HeaderKind header_kind,
        const std::filesystem::path& output_parent_folder,
        const CppCodeBuilder::HostToEnclaveContent& host_to_enclave_content,
        const CppCodeBuilder::EnclaveToHostContent& enclave_to_host_content)
    {
        std::string header_content{};

        if (header_kind == HeaderKind::Vtl1)
        {
            header_content = std::format(
                c_vtl1_trusted_func_declarations_header,
                c_autogen_header_string,
                m_generated_namespace_name,
                m_generated_namespace_name,
                host_to_enclave_content.m_vtl1_trusted_function_declarations);
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
        }

        SaveFileToOutputFolder("Trusted.h", output_parent_folder, header_content);
    }

    void CppCodeGenerator::SaveUntrustedHeader(
        CppCodeBuilder::HeaderKind header_kind,
        const std::filesystem::path& output_parent_folder,
        const CppCodeBuilder::EnclaveToHostContent& enclave_to_host_content)
    {
        std::string sub_namespace_name{};
        std::string sub_namespace_content{};
        std::string includes {};

        if (header_kind == HeaderKind::Vtl1)
        {
            sub_namespace_name = "Stubs";
            includes = R"(<VbsEnclaveABI\Enclave\EnclaveHelpers.h>)";
            sub_namespace_content = enclave_to_host_content.m_vtl1_stubs_for_vtl0_untrusted_functions;
        }
        else
        {
            sub_namespace_name = "Implementation";
            includes = R"(<VbsEnclaveABI\Host\HostHelpers.h>)";
            sub_namespace_content = enclave_to_host_content.m_vtl0_untrusted_function_declarations;
        }

        std::string header_content = std::format(
            c_untrusted_stubs_header_template,
            c_autogen_header_string,
            includes,
            m_generated_namespace_name,
            sub_namespace_name,
            m_generated_namespace_name,
            sub_namespace_content);

        SaveFileToOutputFolder("Untrusted.h", output_parent_folder, header_content);
    }

    void CppCodeGenerator::SaveAbiDefinitionsHeader(
        CppCodeBuilder::HeaderKind header_kind,
        const std::filesystem::path& output_parent_folder,
        const CppCodeBuilder::HostToEnclaveContent& host_to_enclave_content,
        const CppCodeBuilder::EnclaveToHostContent& enclave_to_host_content)
    {
        std::string namespace_content {};
        std::string includes {};

        if (header_kind == HeaderKind::Vtl1)
        {
            namespace_content = host_to_enclave_content.m_vtl1_abi_functions;
            includes = R"(<VbsEnclave\Enclave\Trusted.h>)";
        }
        else
        {
            namespace_content = enclave_to_host_content.m_vtl0_abi_functions;
            includes = R"(<VbsEnclave\HostApp\Untrusted.h>)";
        }

        std::string header_content = std::format(
            c_abi_definitions_stubs_header_template,
            c_autogen_header_string,
            includes,
            m_generated_namespace_name,
            m_generated_namespace_name,
            namespace_content);

        SaveFileToOutputFolder("AbiDefinitions.h", output_parent_folder, header_content);
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

    void CppCodeGenerator::CompileFlatbufferFile(std::filesystem::path save_location)
    {
        auto flatbuffer_schema_path = (save_location / c_flatbuffer_fbs_filename).generic_string();

        std::string flatbuffer_args = std::format(R"({} -o "{}" "{}")", c_cpp_gen_args, save_location.generic_string(), flatbuffer_schema_path);
        InvokeFlatbufferCompiler(m_flatbuffer_compiler_path, flatbuffer_args);
    }
}
