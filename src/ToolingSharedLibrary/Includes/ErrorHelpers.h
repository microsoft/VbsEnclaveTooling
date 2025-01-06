// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once
#include <pch.h>

namespace ErrorHelpers
{
    static const std::string s_warning_prefix = "Warning: ";
    static const std::string s_info_prefix = "Info: ";
    static const std::string s_error_prefix = "Error: ";

    enum class Statuses
    {
        Info,
        Warning,
        Error,
    };

    enum class ErrorIds : std::uint32_t
    {
        Success = 0,
        LanguageNoMoreArgs,
        UnsupportedLanguage,
        EdlNoMoreArgs,
        EdlDoesNotExist,
        NotAnEdlFile,
        OutputDirNoMoreArgs,
        OutputDirNotADirectory,
        ErrorHandlingNoMoreArgs,
        ErrorHandlingInvalidType,
        InvalidArgument,
        IncorrectNonHelpArgsProvided,
        MissingArgument,
    };

    struct ErrorIdsHash
    {
        std::size_t operator()(ErrorIds e) const
        {
            return std::hash<std::uint32_t>()(static_cast<std::uint32_t>(e));
        }
    };

    // When updating these make sure you update ErrorHelpersTests.cpp as well.
    static const std::unordered_map<ErrorIds, std::string, ErrorIdsHash> c_error_messages =
    {
        // Command line parsing errors
        { ErrorIds::LanguageNoMoreArgs,"Unable to find codegen language of choice. No more commandline arguments available to find supported language." },
        { ErrorIds::UnsupportedLanguage,"Language '{}' is not supported." },
        { ErrorIds::EdlNoMoreArgs,"Unable to find edl file path. No more commandline arguments available to find edl path." },
        { ErrorIds::EdlDoesNotExist,"The path to the provided .edl file '{}' does not exist." },
        { ErrorIds::NotAnEdlFile,"The path '{}' must be a path to a .edl file." },
        { ErrorIds::OutputDirNoMoreArgs,"Unable to find output directory. No more commandline arguments available to find output directory." },
        { ErrorIds::OutputDirNotADirectory,"The path '{}' must be a directory that exists. Error code : '{}'" },
        { ErrorIds::ErrorHandlingNoMoreArgs,"Unable to find error handling argument. No more commandline arguments available." },
        { ErrorIds::ErrorHandlingInvalidType,"Error handling type '{}' invalid." },
        { ErrorIds::InvalidArgument,"Unknown argument: {}" },
        { ErrorIds::IncorrectNonHelpArgsProvided,"VbsEnclaveTooling.exe expects '{}' arguments when '-h' is not used. Only found: '{}'" },
        { ErrorIds::MissingArgument,"Missing arguments. Use '-h' for usage." },
    };

    template<typename... Args>
    static std::string inline GetErrorMessageById(ErrorIds id, Args&&... args)
    {
        // format the error and its arguments
        auto& message = c_error_messages.at(id);
        return std::vformat(message, std::make_format_args(args...));
    }

    static void inline PrintStatus(const Statuses& status, const std::string& message)
    {
        if (status == Statuses::Info)
        {
            std::cout << s_info_prefix + message << std::endl;
        }
        else if (status == Statuses::Warning)
        {
            std::cout << s_warning_prefix + message << std::endl;
        }
        else
        {
            std::cerr << s_error_prefix + message << std::endl;
        }
    }

    template<typename... Args>
    static void inline PrintError(ErrorIds id, Args&&... args)
    {
        if (!(c_error_messages.contains(id)))
        {
            std::cerr << "Invalid error ID: " << static_cast<uint32_t>(id) << std::endl;
            return;
        }

        // format the error and its arguments
        PrintStatus(Statuses::Error, GetErrorMessageById(id, std::forward<Args>(args)...));
    }
}
