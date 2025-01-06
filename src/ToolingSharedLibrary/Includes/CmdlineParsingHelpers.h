// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once
#include <pch.h>
#include "ErrorHelpers.h"

using namespace ErrorHelpers;

#define PRINT_AND_RETURN_ERROR(id, ...)  \
    PrintError(id, __VA_ARGS__);          \
    return id;

namespace CmdlineParsingHelpers
{   
    static inline void PrintUsage() {
        std::cout
            << "\n"
            << "Usage: vbsenclavetooling.exe --Language <cpp> --EdlPath <filePath.edl> --ErrorHandling [ErrorCode | Exception]\n"
            << "--OutputDirectory <DirectoryPath>\n"
            << "Mandatory arguments:\n"
            << "  --Language [cpp]                          The progamming language that will be used in the generated code\n"
            << "  --EdlPath <filePath.edl>                  Absolute path to the .edl file that we should use to generate code in the language outlined in '--language'\n"
            << "  --ErrorHandling [ErrorCode | Exception]   The error handling the generated code should use\n"
            << "  --OutputDirectory <DirectoryPath>         Absolute path to directory where all generated files should be placed.\n"
            << "\n"
            << "Optional arguments:\n"
            << "  -h, --help                                Print this help message\n"
            << std::endl;
    }

    enum class ErrorHandlingKind: std::uint32_t
    {
        Unknown,
        ErrorCode,
        Exception,
    };

    enum class SupportedLanguageKind : std::uint32_t
    {
        Unknown,
        Cpp,
    };

    static ErrorIds inline GetSupportedLanguageForCodeGen(
        std::uint32_t index,
        char* args[],
        std::uint32_t args_size,
        SupportedLanguageKind& supported_language)
    {
        supported_language = SupportedLanguageKind::Unknown;
        if (index >= args_size)
        {
            PRINT_AND_RETURN_ERROR(ErrorIds::LanguageNoMoreArgs);
        }

        std::string language{args[index]};
        if (language == "c++" || language == "C++")
        {
            supported_language = SupportedLanguageKind::Cpp;
            return ErrorIds::Success;
        }
        
        PrintError(ErrorIds::UnsupportedLanguage, language);
        PRINT_AND_RETURN_ERROR(ErrorIds::UnsupportedLanguage, language);
    }

    static ErrorIds inline GetEdlPathFromArgs(
        std::uint32_t index,
        char* args[],
        std::uint32_t args_size,
        std::string& edl_path)
    {
        edl_path = "";
        if (index >= args_size)
        {
            PRINT_AND_RETURN_ERROR(ErrorIds::EdlNoMoreArgs);
        }

        std::filesystem::path item_path(args[index]);

        // Check if the item exists
        if (!std::filesystem::exists(item_path))
        {
            PRINT_AND_RETURN_ERROR(ErrorIds::EdlDoesNotExist, item_path.generic_string());
        }

        // Check if the file is a regular file (not a directory)
        auto extension = item_path.extension();
        if (!std::filesystem::is_regular_file(item_path) || extension != L".edl")
        {
            PRINT_AND_RETURN_ERROR(ErrorIds::NotAnEdlFile, item_path.generic_string());
        }

        edl_path = args[index];
        return ErrorIds::Success;
    }

    static ErrorIds inline GetPathToOutputDirectoryFromArgs(
        std::uint32_t index,
        char* args[],
        std::uint32_t args_size,
        std::string& directory)
    {
        directory = "";
        if (index >= args_size)
        {
            PRINT_AND_RETURN_ERROR(ErrorIds::OutputDirNoMoreArgs);
        }

        std::filesystem::path item_path(args[index]);
        std::error_code error_code{};
        if (!std::filesystem::is_directory(item_path, error_code))
        {
            PRINT_AND_RETURN_ERROR(ErrorIds::OutputDirNotADirectory, item_path.generic_string(), error_code.value());
        }

        directory = args[index];
        return ErrorIds::Success;
    }

    static ErrorIds inline GetErrorHandlingFromArg(
        std::uint32_t index,
        char* args[],
        std::uint32_t args_size,
        ErrorHandlingKind& errorKind)
    {
        errorKind = ErrorHandlingKind::Unknown;
        if (index >= args_size)
        {
            PRINT_AND_RETURN_ERROR(ErrorIds::ErrorHandlingNoMoreArgs);
        }

        std::string error_handling(args[index]);

        if(error_handling == "ErrorCode")
        {
            errorKind = ErrorHandlingKind::ErrorCode;
            return ErrorIds::Success;
        }
        else if (error_handling == "Exception")
        {
            errorKind = ErrorHandlingKind::Exception;
            return ErrorIds::Success;
        }
        
        PRINT_AND_RETURN_ERROR(ErrorIds::ErrorHandlingInvalidType, error_handling);
    }
}
