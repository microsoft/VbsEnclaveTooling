// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once
#include <pch.h>
#include "CmdlineParsingHelpers.h"

namespace CmdlineParsingHelpers
{
    class CmdlineArgumentsParser
    {
    public:
        CmdlineArgumentsParser(int argc, char* argv[]);

        bool ShouldDisplayHelp() const {return m_should_display_help; }
        
        std::string_view EdlFilePath() const { return m_edl_path; }

        std::string_view OutDirectory() const { return m_out_directory; }

        std::string_view Vtl0ClassName() const { return m_vtl0_class_name; }

        std::string_view GeneratedNamespace() const { return m_generated_namespace_name; }

        ErrorHandlingKind ErrorHandling() const { return m_error_handling_kind; }

        VirtualTrustLayerKind VirtualTrustLayer() const { return m_virtual_trust_layer_kind; }

        SupportedLanguageKind SupportedLanguage() const { return m_supported_language; }

        bool ParseSuccessful() const { return m_parse_successful; }

        private:
            bool ParseArguments(int argc, char* argv[]);
            bool m_parse_successful = false;
            std::string m_edl_path {};
            std::string m_out_directory {};
            ErrorHandlingKind m_error_handling_kind = ErrorHandlingKind::Unknown;
            VirtualTrustLayerKind m_virtual_trust_layer_kind = VirtualTrustLayerKind::Unknown;
            std::string m_vtl0_class_name{};
            std::string m_generated_namespace_name {};
            bool m_should_display_help = false;
            SupportedLanguageKind m_supported_language = SupportedLanguageKind::Unknown;
            const uint32_t m_required_args = 4;
    };
}
