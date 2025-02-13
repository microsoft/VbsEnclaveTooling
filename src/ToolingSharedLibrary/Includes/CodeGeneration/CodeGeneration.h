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

        struct FunctionParameterInfo
        {
            // Contains data needed to package parameters into a tuple so 
            // we can forward them to the developer impl functions.
            std::ostringstream m_types_in_tuple {};
            std::ostringstream m_types_list {};
            std::ostringstream m_names_list {};

            // The following are for copying Out and In/Out tuple type
            // info to and from generated function parameters. Note: if a
            // function has a return type it will always be added as the
            // last tuple value in m_types_to_return_in_tuple.
            std::ostringstream m_types_to_return_in_tuple {};
            std::ostringstream m_names_to_return_in_tuple {};
            std::ostringstream m_copy_tuple_values_into_parameters {};
            std::ostringstream m_copy_parameters_into_tuple_values {};

            // Used to copy forwarded parameters sent from vtl1 to a vtl0 function
            // via a callback.
            std::ostringstream m_copy_vtl1_tuple_values_into_vtl0_heap_tuple{};
            std::ostringstream m_copy_vtl1_parameters_into_vtl0_heap_tuple{};


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

        std::string GetTypeInfoForFunction(
            const Declaration& declaration,
            ParamModifier modifier);

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
            CodeGenFunctionKind function_kind,
            const FunctionParameterInfo& param_info);

        std::string BuildDeveloperTypesHeader(
            const std::unordered_map<std::string, std::shared_ptr<DeveloperType>>& developer_types);

        // Used to gather all needed function parameter information to allow multiple
        // CodeGen functions to reuse saved metadata about a functions parameters without
        // needing to recompute them.
        FunctionParameterInfo GetParametersAndTupleInformation(
            const Function& function,
            FunctionDirection direction);

        // Used to copy parameters that will be forwarded from vtl1 to 
        // vtl0, into a vtl0 heap object before forwarding.
        void SetupCopyOfReturnParameterStatements(
            const Declaration& parameter,
            const std::uint32_t index,
            FunctionParameterInfo& param_info,
            FunctionDirection direction);

        // Used to copy parameters that will be forwarded from vtl1 to 
        // vtl0, into a vtl0 heap object before forwarding.
        void SetupCopyOfForwardedParameterStatements(
            const Declaration& parameter,
            const std::uint32_t index,
            FunctionParameterInfo& param_info,
            FunctionDirection direction);

        // These functions are what the developer will call.
        // This could be a method in the vtl0 enclave class or
        // a static function in vtl1 for a vtl0 callback.
        std::string BuildInitialCallerFunction(
            const Function& function,
            std::string_view abi_function_to_call,
            const FunctionParameterInfo& param_info,
            FunctionDirection direction,
            bool should_be_static);

        // Intended to be used by CallEnclave function and will call
        // another abi impl function.
        std::string BuildAbiBoundaryFunction(
            const Function& function,
            std::string_view boundary_function_name,
            std::string_view abi_function_to_call,
            bool is_vtl0_callback,
            const FunctionParameterInfo& param_info);

        // Intended to forward parameters to developer Impl functions
        std::string BuildAbiImplFunction(
            const Function& function,
            std::string_view abi_function_name,
            std::string_view call_impl_str,
            const FunctionParameterInfo& param_info);

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
