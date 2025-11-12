// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once 
#include <pch.h>
#include <Edl\Structures.h>
#include <CmdlineParsingHelpers.h>
#include <CodeGeneration\Rust\Constants.h>
#include <CodeGeneration\Rust\CodeGeneration.h>
#include <CodeGeneration\Flatbuffers\BuilderHelpers.h>
#include <CodeGeneration\Flatbuffers\Constants.h>
#include <sstream>

using namespace EdlProcessor;
using namespace CodeGeneration::Flatbuffers;
using namespace CmdlineParsingHelpers;

namespace CodeGeneration::Rust
{
    using namespace CodeBuilder;

    void RustCodeGenerator::Generate()
    {
        std::string cargo_toml_content {};
        std::string lib_rs_content {};
        if (m_virtual_trust_layer_kind == VirtualTrustLayerKind::Enclave)
        {
            std::string crate_name = std::format("{}_enclave_gen", m_generated_namespace_name);
            cargo_toml_content = std::format(c_cargo_toml_content, crate_name, c_enclave_crate_dep);
            lib_rs_content = std::format(c_enclave_lib_rs, c_autogen_header_string);
        }
        else if (m_virtual_trust_layer_kind == VirtualTrustLayerKind::HostApp)
        {
            std::string crate_name = std::format("{}_host_gen", m_generated_namespace_name);
            cargo_toml_content = std::format(c_cargo_toml_content, crate_name, c_host_crate_dep);
            lib_rs_content = std::format(c_host_lib_rs, c_autogen_header_string);
        }
        else
        {
            throw CodeGenerationException(ErrorId::VirtualTrustLayerInvalidType);
        }

        // Save the Cargo.toml c_dev_types_file
        std::string gen_crate_name = std::format("{}_gen", m_generated_namespace_name);
        auto crate_location = m_output_folder_path / gen_crate_name;
        SaveFileToOutputFolder("Cargo.toml", crate_location, cargo_toml_content);

        auto src_location = crate_location / "src";
        auto implementation_location = src_location / "implementation";
        GenerateImplementationModules(implementation_location);

        auto abi_location = src_location / "abi";
        GenerateAbiModules(src_location, abi_location);

        // Save the lib.rs file
        SaveFileToOutputFolder("lib.rs", src_location, lib_rs_content);
    }

    void RustCodeGenerator::GenerateImplementationModules(
        const std::filesystem::path& implementation_location)
    {
        std::string developer_types_file = GenerateDeveloperTypesModuleFile(
            m_generated_namespace_name,
            m_virtual_trust_layer_kind,
            m_edl.m_developer_types);

        // Save developer types module file
        SaveFileToOutputFolder(c_types_file_name, implementation_location, developer_types_file);

        // Save implementation file
        std::string impl_rs_content = std::format(
            c_implementation_mod_rs,
            c_autogen_header_string);

        SaveFileToOutputFolder("mod.rs", implementation_location, impl_rs_content);
    }

    void RustCodeGenerator::GenerateAbiModules(
        const std::filesystem::path& src_location,
        const std::filesystem::path& abi_location)
    {
        auto abi_developer_types = CreateDeveloperTypesForABIFunctions(
            m_edl.m_trusted_functions,
            m_edl.m_untrusted_functions);

        GenerateFlatbufferComponents(abi_developer_types, abi_location);

        // Save function abi structs types module file
        std::string abi_types_file = GenerateAbiTypesModuleFile(
            m_generated_namespace_name,
            m_virtual_trust_layer_kind,
            abi_developer_types);

        SaveFileToOutputFolder(c_abi_types_file_name, abi_location, abi_types_file);

        // Generate abi module file
        std::string abi_rs_content = std::format(c_abi_mod_rs, c_autogen_header_string);
        SaveFileToOutputFolder("mod.rs", abi_location, abi_rs_content);
    }

    void RustCodeGenerator::GenerateFlatbufferComponents(
        const std::vector<DeveloperType>& abi_developer_types,
        const std::filesystem::path& abi_location)
    {
        // Save flatbuffer schema files
        auto flatbuffer_schema = GenerateFlatbufferSchema(
            m_generated_namespace_name,
            m_edl.m_developer_types,
            abi_developer_types);

        auto flatbuffer_location = abi_location / "flatbuffer_gen";
        SaveFileToOutputFolder(c_flatbuffer_fbs_filename, flatbuffer_location, flatbuffer_schema);
        SaveFileToOutputFolder(c_abi_flatbuffers_file_name, flatbuffer_location, c_abi_flatbuffers_content);

        // Generate flatbuffer module using compiler
        CompileFlatbufferFile(m_flatbuffer_compiler_path, c_rust_gen_args, flatbuffer_location);

        // Generate wrapper module for flatbuffer generated module.
        auto pack_module = GenerateFlatbuffersWrapperModuleFile(
            m_generated_namespace_name,
            abi_developer_types);

        SaveFileToOutputFolder(c_flatbuffers_module_name, abi_location, pack_module);
    }
}
