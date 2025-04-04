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
            << "--OutputDirectory <DirectoryPath> --VirtualTrustLayer [HostApp | Enclave] --Vtl0ClassName <name_of_class> \n"
            << "--Namespace <name_of_class> --FlatbuffersCompilerPath <absolute_path_to_file>\n"
            << "\n"
            << "Mandatory arguments:\n"
            << "  --Language [cpp]                                     The progamming language that will be used in the generated code\n"
            << "  --EdlPath <filePath.edl>                             Absolute path to the .edl file that we should use to generate code in the language outlined in '--language'\n"
            << "  --ErrorHandling [ErrorCode | Exception]              The error handling the generated code should use\n"
            << "  --VirtualTrustLayer [HostApp | Enclave]              The virtual trust layer that the code should be generated for.\n"
            << "\n"
            << "Optional arguments:\n"
            << "  -h, --help                                           Print this help message\n"
            << "  --OutputDirectory <DirectoryPath>                    Absolute path to directory where all generated files should be placed. (By default this is the current directory)\n"
            << "  --Vtl0ClassName <name_of_class>                      name of the vtl0 class that will be generated for use by the hostapp. (By default this is the name of the .edl file with the word 'Wrapper' appended to it).\n"
            << "  --Namespace <name_of_class>                          name of the namespace that all generated code will be encapsulated in. (By default this is the name of the .edl file).\n"
            << "  --FlatbuffersCompilerPath <absolute_path_to_file>    Absolute path to the flatbuffer compiler for the language provided in '--Language'. (By default this is the current directory.). The executable must be called flatc.exe and must be an official version of the flatbuffer compiler. \n"
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

    enum class VirtualTrustLayerKind : std::uint32_t
    {
        Unknown,
        HostApp,
        Enclave,
    };

    static ErrorId inline GetSupportedLanguageForCodeGen(
        std::uint32_t index,
        char* args[],
        std::uint32_t args_size,
        SupportedLanguageKind& supported_language)
    {
        supported_language = SupportedLanguageKind::Unknown;
        if (index >= args_size)
        {
            PRINT_AND_RETURN_ERROR(ErrorId::LanguageNoMoreArgs);
        }

        std::string language{args[index]};
        if (language == "c++" || language == "C++")
        {
            supported_language = SupportedLanguageKind::Cpp;
            return ErrorId::Success;
        }
        
        PrintError(ErrorId::UnsupportedLanguage, language);
        PRINT_AND_RETURN_ERROR(ErrorId::UnsupportedLanguage, language);
    }

    static ErrorId inline GetEdlPathFromArgs(
        std::uint32_t index,
        char* args[],
        std::uint32_t args_size,
        std::string& edl_path)
    {
        edl_path = "";
        if (index >= args_size)
        {
            PRINT_AND_RETURN_ERROR(ErrorId::EdlNoMoreArgs);
        }

        std::filesystem::path item_path(args[index]);

        // Check if the item exists
        if (!std::filesystem::exists(item_path))
        {
            PRINT_AND_RETURN_ERROR(ErrorId::EdlDoesNotExist, item_path.generic_string());
        }

        // Check if the file is a regular file (not a directory)
        auto extension = item_path.extension();
        if (!std::filesystem::is_regular_file(item_path) || extension != L".edl")
        {
            PRINT_AND_RETURN_ERROR(ErrorId::NotAnEdlFile, item_path.generic_string());
        }

        edl_path = args[index];
        return ErrorId::Success;
    }

    static ErrorId inline GetPathToOutputDirectoryFromArgs(
        std::uint32_t index,
        char* args[],
        std::uint32_t args_size,
        std::string& directory)
    {
        directory = "";
        if (index >= args_size)
        {
            PRINT_AND_RETURN_ERROR(ErrorId::OutputDirNoMoreArgs);
        }

        directory = args[index];
        return ErrorId::Success;
    }

    static ErrorId inline GetErrorHandlingFromArg(
        std::uint32_t index,
        char* args[],
        std::uint32_t args_size,
        ErrorHandlingKind& errorKind)
    {
        errorKind = ErrorHandlingKind::Unknown;
        if (index >= args_size)
        {
            PRINT_AND_RETURN_ERROR(ErrorId::ErrorHandlingNoMoreArgs);
        }

        std::string error_handling(args[index]);

        if(error_handling == "ErrorCode")
        {
            errorKind = ErrorHandlingKind::ErrorCode;
            return ErrorId::Success;
        }
        else if (error_handling == "Exception")
        {
            errorKind = ErrorHandlingKind::Exception;
            return ErrorId::Success;
        }
        
        PRINT_AND_RETURN_ERROR(ErrorId::ErrorHandlingInvalidType, error_handling);
    }

    static inline ErrorId GetVirtualTrustLayerFromArg(
        std::uint32_t index,
        char* args[],
        std::uint32_t args_size,
        VirtualTrustLayerKind& layer_kind)
    {
        layer_kind = VirtualTrustLayerKind::Unknown;
        if (index >= args_size)
        {
            PRINT_AND_RETURN_ERROR(ErrorId::VirtualTrustLayerNoMoreArgs);
        }

        std::string error_handling(args[index]);

        if (error_handling == "HostApp")
        {
            layer_kind = VirtualTrustLayerKind::HostApp;
            return ErrorId::Success;
        }
        else if (error_handling == "Enclave")
        {
            layer_kind = VirtualTrustLayerKind::Enclave;
            return ErrorId::Success;
        }

        PRINT_AND_RETURN_ERROR(ErrorId::VirtualTrustLayerInvalidType, error_handling);
    }

    static ErrorId inline GetFlatbuffersCompilerPathFromArgs(
        std::uint32_t index,
        char* args[],
        std::uint32_t args_size,
        std::string& flatbuffers_compiler_path)
    {
        flatbuffers_compiler_path = "";
        if (index >= args_size)
        {
            PRINT_AND_RETURN_ERROR(ErrorId::FlatbufferCompilerNoMoreArgs);
        }

        std::filesystem::path item_path(args[index]);

        // Check if the item exists
        if (!std::filesystem::exists(item_path))
        {
            PRINT_AND_RETURN_ERROR(ErrorId::FlatbufferCompilerDoesNotExist, item_path.generic_string());
        }

        // Check if the file is a regular file (not a directory) and at least has the name of the 
        // official compiler exe.
        if (!std::filesystem::is_regular_file(item_path) || item_path.filename().generic_string() != "flatc.exe")
        {
            PRINT_AND_RETURN_ERROR(ErrorId::NotAFile, item_path.generic_string());
        }

        // We will eventually invoke the file with CreateProcess so if it actually isn't an executable
        // it should error out. And if it is one but isn't the flatbuffer compiler then it won't produce
        // the necessary structs/enum types our generated code relies on, which will ultimately make them
        // not compile. So, we're ok with the 3 checks above.
        flatbuffers_compiler_path = args[index];
        return ErrorId::Success;
    }
}
