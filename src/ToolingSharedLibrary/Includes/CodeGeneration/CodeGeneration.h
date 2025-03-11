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
            // Contains data needed to package parameters into a tuple so 
            // we can forward them to the developer impl functions.
            std::ostringstream m_types_in_tuple {};
            std::ostringstream m_param_names_to_add_to_parameter_container {};
            std::ostringstream m_param_names_to_add_to_initial_callers_parameter_container{};
            std::ostringstream m_param_names_to_forward_to_dev_impl {};
            std::ostringstream m_copy_updated_values_into_original_function_parameters {};

            // The following are for copying Out and In/Out value types (non pointer)
            // back into a return tuple to be sent back to the original caller across
            // the trust boundary. For pointer types this is not needed as those values
            // will be updated solely in vtl1.Note: if a
            // function has a return type it will always be added as the
            // last tuple value in m_types_to_return_in_tuple.
            std::ostringstream m_types_to_return_in_tuple {};
            std::ostringstream m_names_to_return_in_tuple {};
            std::vector<std::pair<std::string, size_t>> m_return_tuple_param_indexes{};

            // These are used to copy forwarded parameters sent between a vtl1 function
            // to a vtl0 function and vice versa.
            std::ostringstream m_copy_vtl1_parameters_into_vtl0_heap_tuple{};
            std::ostringstream m_copy_vtl0_parameters_into_vtl1_heap_tuple {};

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

        std::string GetSimpleTypeInfo(const EdlTypeInfo& info);

        std::string BuildArrayType(const Declaration& declaration);

        std::string GetTypeInfoForFunction(const Declaration& declaration, ParameterModifier modifier);

        std::string GetSimpleTypeInfoWithPointerInfo(const EdlTypeInfo& info);

        std::string BuildStructFieldOrFunctionParameter(const Declaration& declaration);

        std::string BuildStructDefinition(const DeveloperType& developer_types);

        std::string BuildStdArrayType(
            std::string_view type,
            const ArrayDimensions& dimensions,
            std::uint32_t index = 0);

        std::string BuildNonArrayType(const Declaration& declaration);

        std::string BuildDeveloperType(const DeveloperType& type);

        std::string BuildFunctionParameters(
            const Function& function,
            FunctionCallInitiator initiator,
            const FunctionParametersInfo& param_info,
            ParameterModifier modifier = ParameterModifier::NoConst);

        std::string BuildDeveloperTypesHeader(
            const std::unordered_map<std::string, std::shared_ptr<DeveloperType>>& developer_types);

        // Used to gather all needed function parameter information to allow multiple
        // CodeGen functions to reuse saved metadata about a functions parameters without
        // needing to recompute them.
        FunctionParametersInfo GetParametersAndTupleInformation(
            const Function& function,
            CallFlowDirection call_direction);

        // Used to copy parameters that will be forwarded from vtl1 to 
        // vtl0, into a vtl0 heap object before forwarding.
        void SetupCopyOfReturnParameterStatements(
            const Declaration& parameter,
            const size_t index,
            std::string_view parameter_type,
            std::string_view size_to_copy,
            FunctionParametersInfo& param_info,
            CallFlowDirection call_direction);

        // Used to copy parameters that will be forwarded from vtl1 to 
        // vtl0 and vice versa.
        void SetupCopyOfForwardParameterStatements(
            const Declaration& parameter,
            const size_t index,
            std::string_view parameter_type,
            std::string_view size_to_copy,
            FunctionParametersInfo& param_info,
            CallFlowDirection call_direction);

        // These functions are what the developer will call from 
        // within the enclave to access the hostApps callback function.
        std::string BuildEnclaveToHostInitialCallerFunction(
            const Function& function,
            std::string_view abi_function_to_call,
            const FunctionParametersInfo& param_info);

        // These functions are what the developer will call from 
        // within the hostApp to access the enclave exported function.
        // These are within the vtl0 generated class.
        std::string BuildHostToEnclaveInitialCallerFunction(
            const Function& function,
            std::string_view abi_function_to_call,
            const FunctionParametersInfo& param_info);

        // Intended to be used by in a CallEnclave Win32 function by the
        // abi layer.
        std::string BuildTrustBoundaryFunction(
            const Function& function,
            std::string_view boundary_function_name,
            std::string_view abi_function_to_call,
            bool is_vtl0_callback,
            const FunctionParametersInfo& param_info);

        // Intended to forward parameters to the developers callback Impl
        // function in vtl0
        std::string BuildVtl0AbiImplFunctionForEnclaveToHost(
            const Function& function,
            std::string_view abi_function_name,
            std::string_view call_impl_str,
            const FunctionParametersInfo& param_info);

        // Intended to forward parameters to the developers exported enclave Impl
        // function in vtl1
        std::string BuildVtl1AbiImplFunctionForHostToEnclave(
            const Function& function,
            std::string_view abi_function_name,
            std::string_view call_impl_str,
            const FunctionParametersInfo& param_info);

        std::string BuildEnclaveModuleDefinitionFile(std::string_view exported_functions);
        
        HostToEnclaveContent BuildHostToEnclaveFunctions(
            std::string_view generated_namespace,
            std::unordered_map<std::string, Function>& functions);

        EnclaveToHostContent BuildEnclaveToHostFunctions(
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
    };

    struct CppCodeGenerator
    {
        CppCodeGenerator(
            const Edl& edl,
            const std::filesystem::path& output_path,
            ErrorHandlingKind error_handling,
            VirtualTrustLayerKind trust_layer,
            std::string_view generated_namespace_name,
            std::string_view generated_vtl0_class_name);

        void Generate();

    private:

        void SaveFileToOutputFolder(
            std::string_view file_name,
            const std::filesystem::path& output_folder,
            std::string_view file_content);

        Edl m_edl {};
        ErrorHandlingKind m_error_handling {};
        std::string_view m_generated_namespace_name{};
        std::string_view m_generated_vtl0_class_name {};
        VirtualTrustLayerKind m_virtual_trust_layer_kind{};
        std::filesystem::path m_output_folder_path {};
    };
}
