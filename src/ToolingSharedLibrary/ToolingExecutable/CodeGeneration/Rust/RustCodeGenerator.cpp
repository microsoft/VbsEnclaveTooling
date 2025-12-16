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
            lib_rs_content = std::format(c_host_lib_rs, c_autogen_header_string, m_generated_vtl0_class_name);
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

        auto stubs_location = src_location / "stubs";
        GenerateStubModules(stubs_location);

        auto abi_location = src_location / "abi";
        GenerateAbiModules(abi_location);

        // Save the lib.rs file
        SaveFileToOutputFolder("lib.rs", src_location, lib_rs_content);

        // Save the build.rs file
        std::string build_rs_content = std::format(c_build_rs_file_content, c_autogen_header_string);

        SaveFileToOutputFolder("build.rs", crate_location, build_rs_content);
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

        std::string impl_module_name {};
        if (m_virtual_trust_layer_kind == VirtualTrustLayerKind::Enclave)
        {
            impl_module_name = "trusted";
            auto trusted_mod = BuildImplTraitModule(m_virtual_trust_layer_kind, m_edl.m_trusted_functions);
            SaveFileToOutputFolder("trusted.rs", implementation_location, trusted_mod);
        }
        else
        {
            impl_module_name = "untrusted";
            auto untrusted_mod = BuildImplTraitModule(m_virtual_trust_layer_kind, m_edl.m_untrusted_functions);
            SaveFileToOutputFolder("untrusted.rs", implementation_location, untrusted_mod);
        }

        // Save implementation file
        std::string impl_rs_content = std::format(
            c_implementation_mod_rs,
            c_autogen_header_string,
            impl_module_name);

        SaveFileToOutputFolder("mod.rs", implementation_location, impl_rs_content);
    }

    void RustCodeGenerator::GenerateStubModules(
        const std::filesystem::path& stubs_location)
    {
        std::string stub_module_name {};
        if (m_virtual_trust_layer_kind == VirtualTrustLayerKind::Enclave)
        {
            stub_module_name = "untrusted";
            auto untrusted_mod = BuildStubTraitModule(
                m_virtual_trust_layer_kind,
                "",
                m_generated_namespace_name,
                m_edl.m_untrusted_functions);

            SaveFileToOutputFolder("untrusted.rs", stubs_location, untrusted_mod);
        }
        else
        {
            stub_module_name = "trusted";
            auto trusted_mod = BuildStubTraitModule(
                m_virtual_trust_layer_kind, 
                m_generated_vtl0_class_name,
                m_generated_namespace_name, 
                m_edl.m_trusted_functions);

            SaveFileToOutputFolder("trusted.rs", stubs_location, trusted_mod);
        }

        std::string stubs_lib_rs_content = std::format(
            c_stubs_lib_mod_rs,
            c_autogen_header_string,
            stub_module_name);

        SaveFileToOutputFolder("mod.rs", stubs_location, stubs_lib_rs_content);
    }

    void RustCodeGenerator::GenerateAbiModules(
        const std::filesystem::path& abi_location)
    {
        auto abi_developer_types = CreateDeveloperTypesForABIFunctions(
            m_edl.m_trusted_functions,
            m_edl.m_untrusted_functions);

        GenerateFlatbufferComponents(abi_developer_types, abi_location);
        GenerateAbiBoundaryModule(abi_location);

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

        // Generate wrapper module for flatbuffer generated module.
        auto pack_module = GenerateFlatbuffersWrapperModuleFile(
            m_generated_namespace_name,
            m_virtual_trust_layer_kind,
            abi_developer_types);

        SaveFileToOutputFolder(c_flatbuffers_module_name, abi_location, pack_module);
    }

    void RustCodeGenerator::GenerateAbiBoundaryModule(
        const std::filesystem::path& abi_location)
    {
        std::string module_content {};
        if (m_virtual_trust_layer_kind == VirtualTrustLayerKind::Enclave)
        {
            module_content = BuildAbiDefinitionModule(
                m_virtual_trust_layer_kind,
                m_generated_namespace_name,
                m_edl.m_trusted_functions);
        }
        else
        {
            module_content = BuildAbiDefinitionModule(
            m_virtual_trust_layer_kind,
            m_generated_namespace_name,
            m_edl.m_untrusted_functions);
        }

        SaveFileToOutputFolder("definitions.rs", abi_location, module_content);
    }
}
