// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once
#include "..\pch.h"
#include <unordered_map>

namespace ErrorHelpers
{
    enum class ErrorIds : std::uint32_t
    {
        LanguageNoMoreArgs = 0,
        UnsupportedLanguage = 1,
        EdlNoMoreArgs = 2,
        EdlDoesNotExist = 3,
        NotAnEdlFile = 4,
        OutputDirNoMoreArgs = 5,
        OutputDirNotADirectory = 6,
        ErrorHandlingNoMoreArgs = 7,
        ErrorHandlingInvalidType = 8,
        InvalidArgument = 9,
        IncorrectNonHelpArgsProvided = 10,
        MissingArgument = 11,
    };

    struct ErrorIdsHash {
        std::size_t operator()(ErrorIds e) const {
            return std::hash<std::uint32_t>()(static_cast<std::uint32_t>(e));
        }
    };

    // When updating these make sure you update ErrorHelpersTests.cpp as well.
    static const std::unordered_map<ErrorIds, std::string, ErrorIdsHash> c_error_messages =
    {
       { ErrorIds::LanguageNoMoreArgs, "Unable to find codegen language of choice. No more commandline arguments available to find supported language." },
       { ErrorIds::UnsupportedLanguage, "Language '{}' is not supported." },
       { ErrorIds::EdlNoMoreArgs, "Unable to find edl file path. No more commandline arguments available to find edl path." },
       { ErrorIds::EdlDoesNotExist, "The path to the provided .edl file '{}' does not exist." },
       { ErrorIds::NotAnEdlFile, "The path '{}' must be a path to a .edl file." },
       { ErrorIds::OutputDirNoMoreArgs, "Unable to find output directory. No more commandline arguments available to find output directory." },
       { ErrorIds::OutputDirNotADirectory, "The path '{}' must be a directory that exists. Error code : '{}'" },
       { ErrorIds::ErrorHandlingNoMoreArgs, "Unable to find error handling argument. No more commandline arguments available." },
       { ErrorIds::ErrorHandlingInvalidType, "Error handling type '{}' invalid." },
       { ErrorIds::InvalidArgument, "Unknown argument: {}" },
       { ErrorIds::IncorrectNonHelpArgsProvided, "VbsEnclaveTooling.exe expects '{}' arguments when '-h' is not used. Only found: '{}'" },
       { ErrorIds::MissingArgument, "Missing arguments. Use '-h' for usage."}
    };

    template<typename... Args>
    static void inline PrintError(ErrorIds id, Args&&... args)
    {
        if (!(c_error_messages.contains(id)))
        {
            std::cerr << "Invalid error ID: " << static_cast<uint32_t>(id) << std::endl;
            return;
        }

        // format the error and its arguments
        auto& message = c_error_messages.at(id);
        std::cerr << std::vformat(message, std::make_format_args(args...)) << std::endl;
    }
}
