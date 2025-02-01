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
        struct TrustFunctionHeaders
        {
            std::string vtl0_class_header_content{};
            std::string vtl1_stub_functions_header_content{};
            std::string vtl1_developer_impls_header_content{};
            std::string vtl1_enclave_module_defintiion_content {};
            std::string vtl1_verifiers_header_content{};
        };

        std::tuple<std::string, std::string, std::string> BuildStartOfDefinition(
            std::string_view type_name,
            std::string_view identifier_name);

        std::string BuildEnumDefinition(const DeveloperType& developer_types);

        std::string GetSimpleTypeInfo(const EdlTypeInfo& info);

        std::string BuildArrayType(const Declaration& declaration);

        std::string GetTypeInfoForFunction(const Declaration& declaration);

        std::string BuildStructFieldOrFunctionParameter(const Declaration& declaration);

        std::string BuildStructDefinition(const DeveloperType& developer_types);

        std::string BuildStdArrayType(
            std::string_view type,
            const ArrayDimensions& dimensions,
            std::uint32_t index = 0);

        std::string BuildNonArrayType(const Declaration& declaration);

        std::string BuildDeveloperType(const DeveloperType& type);
       
        std::string BuildFunctionParameters(const Function& function);

        std::string BuildDeveloperTypesHeader(
            const std::unordered_map<std::string, std::shared_ptr<DeveloperType>>& developer_types);

        std::tuple<std::string, std::string, std::string> GetParametersAndTupleInformation(const Function& function);

        TrustFunctionHeaders BuildHostToEnclaveFunctions(
            std::string_view edl_file_name,
            const std::unordered_map<std::string, Function>& functions);
        
        std::string BuildVTL0HostToEnclaveStubFunctionBody(
            const Function& function,
            std::string_view return_value,
            std::string_view parameter_tuple_type,
            std::string_view tuple_definition);
        
        // This builds a function that uses our ABI calling convention. The developer will call into this 
        // function when attempting to call their enclave impl function from vtl0
        std::string BuildVTL0HostToEnclaveStubFunction(
            const Function& function,
            std::string_view return_value,
            std::string_view parameter_tuple_type,
            std::string_view tuple_definition);

        // This builds the exported function from the enclave that the ABI will use to call into the Impl function
        std::string BuildVTL1HostToEnclaveStubFunction(
            const Function& function, 
            std::string_view return_value,
            std::string_view parameter_tuple_type, 
            std::string_view tuple_definition);

        std::string BuildEnclaveModuleDefinitionFile(std::string_view exported_functions);
        
        // This builds the function declaration for the developers impl function.
        std::tuple <std::string, std::string> BuildVTL1HostToEnclaveImplFunction(
            const Function& function,
            std::string_view return_value,
            std::string_view argument_list_without_types);
        
        // This builds a the function that will copy and verify a functions parameters. 
        // Currently the verification isn't implemented. 
        // TODO: update verfication function to use flatbuffers.
        std::string BuildCopyAndVerifyFunction(const Function& function);
    };

    struct CppCodeGenerator
    {
        CppCodeGenerator(
            const Edl& edl,
            const std::filesystem::path& output_path,
            ErrorHandlingKind error_handling);

        void Generate();

    private:

        void SaveFileToOutputFolder(
            std::string_view file_name,
            const std::filesystem::path& output_folder,
            std::string_view file_content);

        Edl m_edl {};
        ErrorHandlingKind m_error_handling {};
        std::filesystem::path m_output_folder_path {};
    };
}
