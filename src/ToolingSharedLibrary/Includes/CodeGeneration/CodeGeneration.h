// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once 
#include <pch.h>
#include <Edl\Structures.h>
#include <CmdlineParsingHelpers.h>
#include <CmdlineArgumentsParser.h>
#include "CodeGenerationHelpers.h"
#include <Utils\Helpers.h>

using namespace CmdlineParsingHelpers;
using namespace EdlProcessor;

namespace CodeGeneration
{
    namespace CppCodeBuilder
    {
        enum class HeaderKind
        {
            Vtl0,
            Vtl1,
        };

        enum class DataDirectionKind
        {
            Vtl0ToVtl1,
            Vtl1ToVtl0,
        };

        struct HostToEnclaveContent
        {
            std::string m_vtl0_trusted_stub_functions {};
            std::string m_vtl1_trusted_function_declarations {};
            std::string m_vtl1_abi_functions {};
        };

        struct EnclaveToHostContent
        {
            std::string m_vtl0_untrusted_abi_stubs_address_info {};
            std::string m_vtl0_untrusted_function_declarations {};
            std::string m_vtl0_abi_functions {};
            std::string m_vtl1_stubs_for_vtl0_untrusted_functions {};
        };

        // used to start creating a struct, function, or namespace 
        struct Definition
        {
            std::ostringstream m_header;
            std::ostringstream m_body;
            std::ostringstream m_footer;
        };

        struct FunctionParametersInfo
        {
            // Used to moving parameters through trust boundary
            std::ostringstream m_param_to_convert_names {};
            std::ostringstream m_copy_values_from_out_struct_to_original_args {};


            // General info about function that can affect how the the 
            // generated code to copy parameters in the abi layer.
            std::string m_function_return_value{};
            bool m_are_return_params_needed{};
            bool m_function_return_type_void{};
        };

        Definition BuildStartOfDefinition(
            std::string_view type_name,
            std::string_view identifier_name,
            std::size_t num_of_tabs = 0U);

        std::string BuildEnumDefinition(const DeveloperType& developer_types);

        std::string BuildStructField(const Declaration& declaration);

        std::string BuildStructDefinition(
            std::string_view struct_name,
            const std::vector<Declaration>& fields);

        std::string BuildStructMetaData(
            std::string_view generated_parent_namespace,
            std::string_view generated_sub_namespace,
            std::string_view struct_name,
            const std::vector<Declaration>& fields);

        FunctionParametersInfo GetInformationAboutParameters(const Function& function);

        // These functions are what the developer will call 
        // to invoke their impl function on the other side of the
        // trust boundary.
        std::string BuildStubFunction(
            std::string_view developer_namespace_name,
            const Function& function,
            DataDirectionKind directon,
            std::string_view cross_boundary_func_name,
            const FunctionParametersInfo& param_info);

        std::string BuildFunctionParameters(
            const Function& function,
            const FunctionParametersInfo& param_info);

        // Intended to be used by in a CallEnclave Win32 function by the
        // abi layer.
        std::string BuildTrustBoundaryFunction(
            std::string_view developer_namespace_name,
            const Function& function,
            std::string_view abi_function_to_call,
            bool is_vtl0_callback,
            const FunctionParametersInfo& param_info);

        std::string BuildTypesHeader(
            std::string_view developer_namespace_name,
            const OrderedMap<std::string, DeveloperType>& developer_types_map,
            std::span<const DeveloperType> abi_function_developer_types);
        
        HostToEnclaveContent BuildHostToEnclaveFunctions(
            std::string_view generated_namespace,
            const OrderedMap<std::string, Function>& trusted_functions);

        EnclaveToHostContent BuildEnclaveToHostFunctions(
            std::string_view generated_namespace,
            std::string_view generated_class_name,
            const OrderedMap<std::string, Function>& untrusted_functions);

        std::string BuildVtl1ExportedFunctionsSourcefile(
            std::string_view generated_namespace_name,
            const OrderedMap<std::string, Function>& trusted_functions);
    };

    struct CppCodeGenerator
    {
        CppCodeGenerator(
            Edl&& edl,
            const std::filesystem::path& output_path,
            ErrorHandlingKind error_handling,
            VirtualTrustLayerKind trust_layer,
            std::string_view generated_namespace_name,
            std::string_view generated_vtl0_class_name,
            const std::filesystem::path& flatbuffer_compiler_path);

        void Generate();

        void SaveTrustedHeader(
            CppCodeBuilder::HeaderKind header_kind,
            const std::filesystem::path& output_parent_folder,
            const CppCodeBuilder::HostToEnclaveContent& host_to_enclave_content,
            const CppCodeBuilder::EnclaveToHostContent& enclave_to_host_content);

        void SaveUntrustedHeader(
            CppCodeBuilder::HeaderKind header_kind,
            const std::filesystem::path& output_parent_folder,
            const CppCodeBuilder::EnclaveToHostContent& enclave_to_host_content);

        void SaveAbiDefinitionsHeader(
            CppCodeBuilder::HeaderKind header_kind,
            const std::filesystem::path& output_parent_folder,
            const CppCodeBuilder::HostToEnclaveContent& host_to_enclave_content,
            const CppCodeBuilder::EnclaveToHostContent& enclave_to_host_content);

    private:

        void SaveFileToOutputFolder(
            std::string_view file_name,
            const std::filesystem::path& output_folder,
            std::string_view file_content);

        void CompileFlatbufferFile(std::filesystem::path save_location);

        Edl m_edl {};
        std::vector<std::string> m_sdk_trusted_function_abi_names {};
        ErrorHandlingKind m_error_handling {};
        std::string_view m_generated_namespace_name{};
        std::string_view m_generated_vtl0_class_name {};
        VirtualTrustLayerKind m_virtual_trust_layer_kind{};
        std::filesystem::path m_output_folder_path {};
        std::filesystem::path m_flatbuffer_compiler_path {};
    };
}
