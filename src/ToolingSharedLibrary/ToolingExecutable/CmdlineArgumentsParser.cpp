// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <pch.h>
#include <CmdlineArgumentsParser.h>

using namespace ErrorHelpers;
using namespace CmdlineParsingHelpers;

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
        PrintError(ErrorIds::MissingArgument);
        return false;
    }

    bool argument_parse_result = false;
    uint32_t non_help_args_found = 0U;
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
            argument_parse_result = GetSupportedLanguageForCodeGen(++i, argv, argc, m_supported_language);
            non_help_args_found++;
        }
        else if (arg == "--EdlPath")
        {
            argument_parse_result = GetEdlPathFromArgs(++i, argv, argc, m_edl_path);
            non_help_args_found++;
        }
        else if (arg == "--OutputDirectory")
        {
            GetPathToOutputDirectoryFromArgs(++i, argv, argc, m_out_directory);
            non_help_args_found++;
        }
        else if (arg == "--ErrorHandling")
        {
            argument_parse_result = GetErrorHandlingFromArg(++i, argv, argc, m_error_handling_kind);
            non_help_args_found++;
        }
        else
        {
            argument_parse_result = false;
            PrintError(ErrorIds::InvalidArgument, arg);
        }

        if (!argument_parse_result)
        {
            return argument_parse_result;
        }
    }

    if (non_help_args_found != m_non_help_expected_Arg_count)
    {
        PrintError(
            ErrorIds::IncorrectNonHelpArgsProvided,
            m_non_help_expected_Arg_count,
            non_help_args_found);

        return false;
    }

    return true;
}
