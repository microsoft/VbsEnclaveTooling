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
        Edl&& edl,
        const std::filesystem::path& output_path,
        ErrorHandlingKind error_handling,
        VirtualTrustLayerKind trust_layer,
        std::string_view generated_namespace_name,
        std::string_view generated_vtl0_class_name,
        const std::filesystem::path& flatbuffer_compiler_path)
        :   m_edl(std::move(edl)),
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
        std::string enclave_types_header = BuildTypesHeader(
            m_generated_namespace_name,
            m_edl.m_developer_types,
            std::span<const DeveloperType>(abi_function_developer_types));

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
            m_generated_vtl0_class_name,
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
                c_enclave_exports_source,
                save_location / "Abi",
                exported_definitions_source);
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
            m_edl.m_developer_types_insertion_order_list);

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
            m_edl.m_developer_types_insertion_order_list,
            abi_function_developer_types);

        SaveFileToOutputFolder("TypeMetadata.h", abi_save_location, abi_metadata_types_header);

        SaveFileToOutputFolder(c_flatbuffer_fbs_filename, abi_save_location, flatbuffer_schema);
        CompileFlatbufferFile(abi_save_location);
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
        std::string namespace_content {};
        std::string includes {};

        if (header_kind == HeaderKind::Vtl1)
        {
            namespace_content = host_to_enclave_content.m_vtl1_abi_functions;
            includes = c_vtl1_abi_definitions_includes;
        }
        else
        {
            namespace_content = enclave_to_host_content.m_vtl0_abi_functions;
            includes = c_vtl0_abi_definitions_includes;
        }

        std::string header_content = std::format(
            c_abi_definitions_stubs_header_template,
            c_autogen_header_string,
            includes,
            m_generated_namespace_name,
            namespace_content);

        SaveFileToOutputFolder("Definitions.h", output_parent_folder, header_content);
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
