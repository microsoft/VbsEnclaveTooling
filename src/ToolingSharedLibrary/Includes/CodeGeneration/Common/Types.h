// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once 
#include <pch.h>
#include <CodeGeneration\Cpp\Constants.h>
#include <CodeGeneration\Flatbuffers\Constants.h>
#include <Edl\Structures.h>
#include <Edl\Utils.h>
#include <Exceptions.h>
#include <CmdlineParsingHelpers.h>

using namespace CmdlineParsingHelpers;
using namespace CodeGeneration::Flatbuffers;
using namespace EdlProcessor;
using namespace ToolingExceptions;

namespace CodeGeneration::Common
{
    // used to start creating a struct, function, or namespace 
    struct Definition
    {
        std::ostringstream m_header;
        std::ostringstream m_body;
        std::ostringstream m_footer;
    };

    struct CmdlineMetadata
    {
        Edl edl;  // moved into this struct
        std::filesystem::path output_path;
        ErrorHandlingKind error_handling;
        VirtualTrustLayerKind trust_layer;
        std::string generated_namespace_name;
        std::string generated_vtl0_class_name;
        std::filesystem::path flatbuffer_compiler_path;
        SupportedLanguageKind language_kind;
    };

    class CodeGeneratorBase
    {
    public:
        explicit CodeGeneratorBase(CmdlineMetadata& metadata)
            : m_edl(std::move(metadata.edl)),
            m_output_folder_path(std::move(metadata.output_path)),
            m_error_handling(metadata.error_handling),
            m_virtual_trust_layer_kind(metadata.trust_layer),
            m_generated_namespace_name(std::move(metadata.generated_namespace_name)),
            m_generated_vtl0_class_name(std::move(metadata.generated_vtl0_class_name)),
            m_flatbuffer_compiler_path(std::move(metadata.flatbuffer_compiler_path)),
            m_language_kind(metadata.language_kind)
        {
            if (m_output_folder_path.empty())
            {
                m_output_folder_path = std::filesystem::current_path();
            }

            if (m_generated_namespace_name.empty())
            {
                m_generated_namespace_name = m_edl.m_name;
            }

            if (m_generated_vtl0_class_name.empty())
            {
                m_generated_vtl0_class_name =
                    std::format(c_vtl0_enclave_class_name, m_edl.m_name);
            }

            if (m_flatbuffer_compiler_path.empty())
            {
                m_flatbuffer_compiler_path = std::format(
                    c_flatbuffer_compiler_default_path,
                    std::filesystem::current_path().generic_string());
            }
        }

        virtual ~CodeGeneratorBase() = default;

        virtual void Generate() = 0;

    protected:
        Edl m_edl;
        std::filesystem::path m_output_folder_path;
        ErrorHandlingKind m_error_handling;
        VirtualTrustLayerKind m_virtual_trust_layer_kind;
        std::string m_generated_namespace_name;
        std::string m_generated_vtl0_class_name;
        std::filesystem::path m_flatbuffer_compiler_path;
        SupportedLanguageKind m_language_kind;
    };
    
}
