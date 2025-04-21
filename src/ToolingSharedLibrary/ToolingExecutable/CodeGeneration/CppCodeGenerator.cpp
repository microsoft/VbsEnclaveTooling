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
        const std::optional<Edl>& sdk_edl,
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

        if (sdk_edl.has_value())
        {
            for (auto& [name, function] : sdk_edl.value().m_trusted_functions)
            {
                m_sdk_trusted_function_abi_names.push_back(function.abi_m_name);
            }
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
            m_edl.m_developer_types_insertion_order_list,
            abi_function_developer_types);

        auto flatbuffer_schema = GenerateFlatbufferSchema(
            m_edl.m_developer_types_insertion_order_list,
            abi_function_developer_types);

        // Process content from the trusted content.
        auto host_to_enclave_content = BuildHostToEnclaveFunctions(m_generated_namespace_name, m_edl.m_trusted_functions);

        // Process the content from the untrusted functions
        auto enclave_to_host_content = BuildEnclaveToHostFunctions(m_edl.m_untrusted_functions);

        std::filesystem::path save_location{};

        if (m_virtual_trust_layer_kind == VirtualTrustLayerKind::Enclave)
        {
            save_location = enclave_headers_location;

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

            SaveFileToOutputFolder(c_flatbuffer_fbs_filename, enclave_headers_location, flatbuffer_schema);

            auto exports_folder = enclave_headers_location / "Exports";

            std::string exported_declarations_header = BuildVtl1ExportedFunctionDeclarationsHeader(
                m_generated_namespace_name,
                m_edl.m_trusted_functions);

            SaveFileToOutputFolder(
                c_enclave_exports_header,
                exports_folder,
                exported_declarations_header);

            std::string exported_definitions_source = BuildVtl1ExportedFunctionsSourcefile(
                m_generated_namespace_name,
                m_sdk_trusted_function_abi_names,
                m_edl.m_trusted_functions);

            SaveFileToOutputFolder(
                c_enclave_exports_source,
                exports_folder,
                exported_definitions_source);

            std::string boundary_stubs_header = BuildVtl1BoundaryFunctionsStubHeader(
                m_generated_namespace_name,
                m_edl.m_trusted_functions);

            SaveFileToOutputFolder(
                c_stubs_header_for_enclave_exports,
                exports_folder,
                boundary_stubs_header);
        }
        else if (m_virtual_trust_layer_kind == VirtualTrustLayerKind::HostApp)
        {
            save_location = hostapp_headers_location;

            // Add the register callbacks abi function and combine the two streams
            // that contain the vtl0 public class methods.
            std::string callbacks_name = std::format(
                c_vtl1_register_callbacks_abi_export_name,
                m_generated_namespace_name);

            std::string callbacks_name_with_quotes = std::format("{}{}{}",
                "\"",
                callbacks_name,
                "\"");

            std::string vtl0_register_callbacks_abi_function = std::format(
                c_vtl0_register_callbacks_abi_function,
                callbacks_name_with_quotes);

            enclave_to_host_content.m_vtl0_class_public_content 
                << vtl0_register_callbacks_abi_function
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
