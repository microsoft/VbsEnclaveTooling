// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <pch.h>
#include <CmdlineArgumentsParser.h>

using namespace ErrorHelpers;
using namespace CmdlineParsingHelpers;

#define CHECK_SUCCESS(result)  \
    if ((result) != ErrorId::Success) { \
        return false; \
    }

CmdlineArgumentsParser::CmdlineArgumentsParser(int argc, char* argv[])
{
    m_parse_successful = ParseArguments(argc, argv);
}

bool CmdlineArgumentsParser::ParseArguments(int argc, char* argv[])
{
    // When initiating from the commandline, the first argument passed in
    // is the full path of the exe. We expect more argument than one in all
    // our use cases.
    if (argc <= 1)
    {
        PrintError(ErrorId::MissingArgument);
        return false;
    }

    uint32_t args_found = 0U;
    for(int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help")
        {
            // Help is printed in the main function. Ignore everything else.
            m_should_display_help = true;
            return m_should_display_help;
        }
        else if (arg == "--Language")
        {
            CHECK_SUCCESS(GetSupportedLanguageForCodeGen(++i, argv, argc, m_supported_language));
            args_found++;
        }
        else if (arg == "--EdlPath")
        {
            CHECK_SUCCESS(GetEdlPathFromArgs(++i, argv, argc, m_edl_path));
            args_found++;
        }
        else if (arg == "--OutputDirectory")
        {
            CHECK_SUCCESS(GetPathToOutputDirectoryFromArgs(++i, argv, argc, m_out_directory));
            args_found++;
        }
        else if (arg == "--ErrorHandling")
        {
            CHECK_SUCCESS(GetErrorHandlingFromArg(++i, argv, argc, m_error_handling_kind));
            args_found++;
        }
        else if (arg == "--VirtualTrustLayer")
        {
            CHECK_SUCCESS(GetVirtualTrustLayerFromArg(++i, argv, argc, m_virtual_trust_layer_kind));
            args_found++;
        }
        else if (arg == "--Namespace")
        {
            m_generated_namespace_name = argv[++i];
            args_found++;
        }
        else if (arg == "--Vtl0ClassName")
        {
            m_vtl0_class_name = argv[++i];
            args_found++;
        }
        else if (arg == "--ImportDirectories")
        {
            CHECK_SUCCESS(GetImportDirectoriesFromArgs(++i, argv, argc, m_import_directories));
            args_found++;
        }
        else if (arg == "--FlatbuffersCompilerPath")
        {
            CHECK_SUCCESS(GetFlatbuffersCompilerPathFromArgs(++i, argv, argc, m_flatbuffer_compiler_path));
            args_found++;
        }
        else
        {
            PrintError(ErrorId::InvalidArgument, arg);
            return false;
        }
    }

    // Add parent directory by default
    m_import_directories.push_back(m_edl_path.parent_path());

    if (args_found < m_required_args)
    {
        PrintError(
            ErrorId::IncorrectNonHelpArgsProvided,
            m_required_args,
            args_found);

        return false;
    }

    return true;
}
