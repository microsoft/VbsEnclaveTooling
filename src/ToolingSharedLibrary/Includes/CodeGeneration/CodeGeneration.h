// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once 
#include <pch.h>
#include <Edl\Structures.h>
#include <CmdlineParsingHelpers.h>
#include <CmdlineArgumentsParser.h>
#include "CodeGenerationHelpers.h"

using namespace CmdlineParsingHelpers;
using namespace EdlProcessor;

namespace CodeGeneration
{
    inline constexpr std::string_view g_sdk_namespace_name = "veil_abi";

    namespace CppCodeBuilder
    {
        struct HostToEnclaveContent
        {
            std::ostringstream m_vtl0_class_public_content{};
            std::string m_vtl1_stub_functions_header_content{};
            std::ostringstream m_vtl1_developer_declaration_functions {};
            std::ostringstream m_vtl1_abi_impl_functions {};
            std::string m_vtl1_enclave_module_definition_content {};
        };

        struct EnclaveToHostContent
        {
            std::ostringstream m_vtl0_class_public_content {};
            std::ostringstream m_vtl0_class_private_content {};
            std::ostringstream m_vtl1_side_of_vtl0_callback_functions {};
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
            std::ostringstream m_in_and_inout_param_names {};
            std::ostringstream m_copy_values_from_out_struct_to_original_args {};
            std::ostringstream m_params_to_forward_to_dev_impl {};


            // General info about function that can affect how the the 
            // generated code to copy parameters in the abi layer.
            std::string m_function_return_value{};
            bool m_are_return_params_needed{};
            bool m_function_return_type_void{};
        };

        Definition BuildStartOfDefinition(
            std::string_view type_name,
            std::string_view identifier_name);

        std::string BuildEnumDefinition(const DeveloperType& developer_types);

        std::string BuildStructField(const Declaration& declaration);

        std::string BuildStructDefinition(const DeveloperType& developer_types);

        std::string BuildStructDefinitionForABIDeveloperType(
            std::string_view struct_name,
            const std::vector<Declaration>& fields);

        std::string BuildStructDefinitionForNonABIDeveloperType(
            std::string_view struct_name,
            const std::vector<Declaration>& fields);

        FunctionParametersInfo GetInformationAboutParameters(
            const Function& function,
            const std::unordered_map<std::string, DeveloperType>& developer_types);

        // These functions are what the developer will call 
        // to invoke their impl function on the other side of the
        // trust boundary.
        std::string BuildInitialCallerFunction(
            const Function& function,
            std::string_view abi_function_to_call,
            bool should_be_inline,
            const std::unordered_map<std::string, DeveloperType>& developer_types,
            const FunctionParametersInfo& param_info);

        // Intended to forward parameters to the developers callback Impl
        // on the other side of the boundary
        std::string BuildAbiImplFunction(
            const Function& function,
            std::string_view call_impl_str,
            const FunctionParametersInfo& param_info);

        std::string BuildFunctionParameters(
            const Function& function,
            const FunctionParametersInfo& param_info);

        std::string BuildTypesHeader(
            const std::vector<DeveloperType>& developer_types_insertion_list,
            const std::vector<DeveloperType>& abi_function_developer_types);

        // Intended to be used by in a CallEnclave Win32 function by the
        // abi layer.
        std::string BuildTrustBoundaryFunction(
            const Function& function,
            std::string_view abi_function_to_call,
            bool is_vtl0_callback,
            const FunctionParametersInfo& param_info);

        std::string BuildEnclaveModuleDefinitionFile(std::string_view exported_functions);
        
        HostToEnclaveContent BuildHostToEnclaveFunctions(
            std::string_view generated_namespace,
            const std::unordered_map<std::string, DeveloperType>& developer_types,
            std::unordered_map<std::string, Function>& functions);

        EnclaveToHostContent BuildEnclaveToHostFunctions(
            std::string_view generated_namespace,
            std::string_view generated_class_name,
            const std::unordered_map<std::string, DeveloperType>& developer_types,
            std::unordered_map<std::string, Function>& functions);

        std::string CombineAndBuildHostAppEnclaveClass(
            std::string_view generated_class_name,
            std::string_view generated_namespace_name,
            const std::ostringstream& vtl0_class_public_content,
            const std::ostringstream& vtl0_class_private_content);

        std::string CombineAndBuildVtl1ImplementationsHeader(
            std::string_view edl_file_name,
            const std::ostringstream& vtl1_developer_declarations,
            const std::ostringstream& vtl1_callback_impl_functions,
            const std::ostringstream& vtl1_abi_impl_functions);

        std::string BuildVtl1ExportedFunctionsSourcefile(
            std::string_view generated_namespace_name,
            const std::unordered_map<std::string, Function>& developer_functions_to_export);

        std::string BuildVtl1BoundaryFunctionsStubHeader(
            std::string_view generated_namespace_name,
            const std::unordered_map<std::string, Function>& functions);
    };

    struct CppCodeGenerator
    {
        CppCodeGenerator(
            const Edl& edl,
            const std::filesystem::path& output_path,
            ErrorHandlingKind error_handling,
            VirtualTrustLayerKind trust_layer,
            std::string_view generated_namespace_name,
            std::string_view generated_vtl0_class_name,
            std::string_view flatbuffer_compiler_path);

        void Generate();

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
