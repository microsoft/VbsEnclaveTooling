// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once 
#include <pch.h>
#include <Edl\Structures.h>
#include <Edl\Utils.h>
#include <CodeGeneration\Rust\Constants.h>
#include <CodeGeneration\Rust\CodeGeneration.h>
#include <CodeGeneration\Flatbuffers\BuilderHelpers.h>
#include <CodeGeneration\Flatbuffers\Constants.h>
#include <sstream>

using namespace EdlProcessor;
using namespace CodeGeneration::Flatbuffers;

namespace CodeGeneration::Rust
{
    void RustCodeGenerator::Generate()
    {
        using namespace CodeBuilder;

        std::string cargo_toml_content{};
        if (m_virtual_trust_layer_kind == VirtualTrustLayerKind::Enclave)
        {
            cargo_toml_content = std::format(c_cargo_toml_content, m_edl.m_name, c_enclave_crate_dep);
        }
        else if (m_virtual_trust_layer_kind == VirtualTrustLayerKind::HostApp)
        {
            cargo_toml_content = std::format(c_cargo_toml_content, m_edl.m_name, c_host_crate_dep);
        }
        else
        {
            throw CodeGenerationException(ErrorId::VirtualTrustLayerInvalidType);
        }

        std::string gen_crate_name = std::format("{}_generated", m_edl.m_name);
        auto crate_location = m_output_folder_path / gen_crate_name;

        // Save the Cargo.toml file
        SaveFileToOutputFolder("Cargo.toml", crate_location, cargo_toml_content);
        auto src_location = crate_location / "src";
        auto abi_location = src_location / "abi";
        auto implementation_location = src_location / "implementation";

        std::string developer_types_file = GenerateDeveloperTypesModuleFile(
            m_generated_namespace_name,
            m_edl.m_developer_types);

        // Save developer types module file
        SaveFileToOutputFolder(c_types_file_name, implementation_location, developer_types_file);
    
        auto abi_function_developer_types = CreateDeveloperTypesForABIFunctions(
            m_edl.m_trusted_functions,
            m_edl.m_untrusted_functions);

        // Save function abi structs types module file
        std::string abi_types_file = GenerateAbiTypesModuleFile(
            m_generated_namespace_name,
            abi_function_developer_types);

        SaveFileToOutputFolder(c_types_file_name, abi_location, abi_types_file);
        
        // Save flatbuffer our schema files
        auto flatbuffer_schema = GenerateFlatbufferSchema(
            m_generated_namespace_name,
            m_edl.m_developer_types,
            abi_function_developer_types);

        auto generated_flatbuffer_location = abi_location / "flatbuffers" / "flatbuffer_gen";
        SaveFileToOutputFolder(c_flatbuffer_fbs_filename, generated_flatbuffer_location, flatbuffer_schema);
        SaveFileToOutputFolder(c_abi_flatbuffers_file_name, generated_flatbuffer_location, c_abi_flatbuffers_content);

        // Generate flatbuffer module using compiler
        CompileFlatbufferFile(m_flatbuffer_compiler_path, c_rust_gen_args, generated_flatbuffer_location);
        
        // Generate flatbuffer pack module file
        auto pack_module = GenerateFlatbuffersPackModuleFile(m_generated_namespace_name, abi_function_developer_types);
        SaveFileToOutputFolder(c_flatbuffers_module_name, abi_location / "flatbuffers", pack_module);
    }
}