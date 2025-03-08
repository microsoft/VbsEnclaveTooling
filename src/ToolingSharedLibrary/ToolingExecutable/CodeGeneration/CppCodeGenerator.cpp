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
            m_flatbuffer_compiler_path = std::move(std::format(
                c_flatbuffer_compiler_default_path,
                std::filesystem::current_path().generic_string()));
        }
    }

    void CppCodeGenerator::Generate()
    {
        std::string enclave_headers_output = std::format(c_output_folder_for_generated_trusted_functions, m_edl.m_name);
        std::string hostapp_headers_output = std::format(c_output_folder_for_generated_untrusted_functions, m_edl.m_name);
        auto enclave_headers_location = m_output_folder_path / enclave_headers_output;
        auto hostapp_headers_location = m_output_folder_path / hostapp_headers_output;

        std::ostringstream developer_structs = CreateDeveloperTypeStructs(
            m_edl.m_developer_types_insertion_order_list);

        auto flatbuffer_schema = BuildInitialFlatbufferSchemaContent(m_edl.m_developer_types_insertion_order_list);

        // Process content from the trusted content.
        auto host_to_enclave_content = BuildHostToEnclaveFunctions(
            m_generated_namespace_name,
            flatbuffer_schema,
            developer_structs,
            m_edl.m_developer_types,
            m_edl.m_trusted_functions);

        // Process the content from the untrusted functions
        auto enclave_to_host_content = BuildEnclaveToHostFunctions(
            flatbuffer_schema,
            developer_structs,
            m_edl.m_developer_types,
            m_edl.m_untrusted_functions);

        flatbuffer_schema << c_flatbuffer_root_table << c_flatbuffer_root_type;

        // Create developer types. This is shared between
        // the HostApp and the enclave.
        auto enclave_types_header = BuildTypesHeader(developer_structs);

        if (m_virtual_trust_layer_kind == VirtualTrustLayerKind::Enclave)
        {
            SaveFileToOutputFolder(
                c_trust_vtl1_stubs_header,
                enclave_headers_location,
                host_to_enclave_content.m_vtl1_stub_functions_header_content);

            SaveFileToOutputFolder(
                c_output_module_def_file_name,
                enclave_headers_location,
                host_to_enclave_content.m_vtl1_enclave_module_definition_content);

            auto vtl1_impl_header = CombineAndBuildVtl1ImplementationsHeader(
               m_generated_namespace_name,
               host_to_enclave_content.m_vtl1_developer_declaration_functions,
               enclave_to_host_content.m_vtl1_side_of_vtl0_callback_functions,
               host_to_enclave_content.m_vtl1_abi_impl_functions);

            SaveFileToOutputFolder(
                c_trusted_vtl1_impl_header,
                enclave_headers_location,
                vtl1_impl_header);

            SaveFileToOutputFolder(
                c_developer_types_header,
                enclave_headers_location,
                enclave_types_header);

            SaveAndCompileFlatbufferFile(enclave_headers_location, std::move(flatbuffer_schema));
        }
        else if (m_virtual_trust_layer_kind == VirtualTrustLayerKind::HostApp)
        {
            // Add the register callbacks abi function and combine the two streams
            // that contain the vtl0 public class methods.
            enclave_to_host_content.m_vtl0_class_public_content 
                << c_vtl0_register_callbacks_abi_function
                << host_to_enclave_content.m_vtl0_class_public_content.str();

            auto vtl0_class_header = CombineAndBuildHostAppEnclaveClass(
                m_generated_vtl0_class_name,
                m_generated_namespace_name,
                enclave_to_host_content.m_vtl0_class_public_content,
                enclave_to_host_content.m_vtl0_class_private_content);

            SaveFileToOutputFolder(
                c_untrusted_vtl0_stubs_header,
                hostapp_headers_location,
                vtl0_class_header);

            SaveFileToOutputFolder(
                c_developer_types_header,
                hostapp_headers_location,
                enclave_types_header);

            SaveAndCompileFlatbufferFile(hostapp_headers_location, std::move(flatbuffer_schema));
        }
        else
        {
            throw CodeGenerationException(ErrorId::VirtualTrustLayerInvalidType);
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

    void CppCodeGenerator::SaveAndCompileFlatbufferFile(
        std::filesystem::path save_location,
        std::ostringstream flatbuffer_schema)
    {
        SaveFileToOutputFolder(c_flatbuffer_fbs_filename, save_location, flatbuffer_schema.str());
        auto flatbuffer_schema_path = (save_location / c_flatbuffer_fbs_filename).generic_string();

        std::string flatbuffer_args = std::format(R"({} -o "{}" "{}")", c_cpp_gen_args, save_location.generic_string(), flatbuffer_schema_path);
        InvokeFlatbufferCompiler(m_flatbuffer_compiler_path.generic_string(), flatbuffer_args);
    }
}
