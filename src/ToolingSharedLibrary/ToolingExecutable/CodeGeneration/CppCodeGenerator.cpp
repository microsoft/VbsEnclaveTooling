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
            m_edl.m_trusted_functions,
            m_edl.m_untrusted_functions);

        // Create developer types. This is shared between
        // the HostApp and the enclave.
        std::string enclave_types_header = BuildTypesHeader(
            m_generated_namespace_name,
            m_edl.m_developer_types_insertion_order_list,
            abi_function_developer_types);

        auto flatbuffer_schema = GenerateFlatbufferSchema(
            m_edl.m_developer_types_insertion_order_list,
            abi_function_developer_types);

        // Process content from the trusted content.
        auto host_to_enclave_content = BuildHostToEnclaveFunctions(
            m_generated_namespace_name,
            m_edl.m_developer_types,
            m_edl.m_trusted_functions);

        // Process the content from the untrusted functions
        auto enclave_to_host_content = BuildEnclaveToHostFunctions(
            m_generated_namespace_name, 
            m_generated_vtl0_class_name,
            m_edl.m_developer_types,
            m_edl.m_untrusted_functions);

        std::filesystem::path save_location{};

        if (m_virtual_trust_layer_kind == VirtualTrustLayerKind::Enclave)
        {
            save_location = enclave_headers_location;

            SaveFileToOutputFolder(
                c_trust_vtl1_exported_stubs_header,
                enclave_headers_location,
                host_to_enclave_content.m_vtl1_stub_functions_header_content);

            auto vtl1_trusted_definitions_header = std::format(
                c_vtl1_trusted_namespace,
                c_autogen_header_string, 
                m_generated_namespace_name,
                host_to_enclave_content.m_vtl1_developer_declaration_functions.str());

            SaveFileToOutputFolder(
                c_trusted_vtl1_definitions_header,
                enclave_headers_location,
                vtl1_trusted_definitions_header);

            auto vtl1_abi_stub_header = std::format(
                c_vtl1_abi_definitions_namespace,
                c_autogen_header_string, 
                m_generated_namespace_name,
                host_to_enclave_content.m_vtl1_abi_impl_functions.str());

            SaveFileToOutputFolder(
                c_trusted_abi_stubs_header,
                enclave_headers_location,
                vtl1_abi_stub_header);

            auto vtl1_untrusted_stub_header = std::format(
                c_vtl1_untrusted_namespace,
                c_autogen_header_string,
                m_generated_namespace_name,
                enclave_to_host_content.m_vtl1_side_of_vtl0_callback_functions.str());

            SaveFileToOutputFolder(
                c_untrusted_vtl1_stubs_header,
                enclave_headers_location,
                vtl1_untrusted_stub_header);

            SaveFileToOutputFolder(
                c_developer_types_header,
                enclave_headers_location,
                enclave_types_header);

            SaveFileToOutputFolder(c_flatbuffer_fbs_filename, enclave_headers_location, flatbuffer_schema);

            auto exports_folder = enclave_headers_location / "Exports";

            std::string exported_definitions_source = BuildVtl1ExportedFunctionsSourcefile(
                m_generated_namespace_name,
                m_edl.m_trusted_functions);

            SaveFileToOutputFolder(
                std::format(c_enclave_exports_source, m_generated_namespace_name),
                exports_folder,
                exported_definitions_source);

            std::string boundary_stubs_header = BuildVtl1BoundaryFunctionsStubHeader(
                m_generated_namespace_name,
                m_edl.m_trusted_functions);

            SaveFileToOutputFolder(
                std::format(c_stubs_header_for_enclave_exports, m_generated_namespace_name),
                exports_folder,
                boundary_stubs_header);
        }
        else if (m_virtual_trust_layer_kind == VirtualTrustLayerKind::HostApp)
        {
                    /*return EnclaveToHostContent {
            std::move(vtl0_class),
            std::move(vtl1_side_of_vtl0_callback_functions),
            std::move(vtl0_abi_boundary_functions),
            std::move(vtl0_abi_impl_callback_functions)*/

            save_location = hostapp_headers_location;

            //std::string host_abi_definitions = 
            enclave_to_host_content.m_vtl0_class;
            //<< vtl0_register_callbacks_abi_function;
            //<< host_to_enclave_content.m_vtl0_class_public_content.str();

            auto vtl0_class_header = BuildHostAppEnclaveClass(
                m_generated_vtl0_class_name,
                m_generated_namespace_name,
                enclave_to_host_content.m_vtl0_class);

            SaveFileToOutputFolder(
                c_untrusted_vtl0_stubs_header,
                hostapp_headers_location,
                vtl0_class_header);

            auto vtl0_abi_definitions = std::format(
                c_vtl0_abi_definitions,
                c_autogen_header_string,
                m_generated_namespace_name,
                enclave_to_host_content.vtl0_abi_impl_callback_functions,
                enclave_to_host_content.vtl0_abi_boundary_functions);

            SaveFileToOutputFolder(
                c_abi_stubs_header,
                hostapp_headers_location,
                vtl0_abi_definitions);

            SaveFileToOutputFolder(
                c_developer_types_header,
                hostapp_headers_location,
                enclave_types_header);

            SaveFileToOutputFolder(c_flatbuffer_fbs_filename, hostapp_headers_location, flatbuffer_schema);
        }
        else
        {
            throw CodeGenerationException(ErrorId::VirtualTrustLayerInvalidType);
        }

        CompileFlatbufferFile(save_location);
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
