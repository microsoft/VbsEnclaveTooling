// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once
#include <pch.h>

namespace ErrorHelpers
{
    static const std::string s_warning_prefix = "Warning: ";
    static const std::string s_info_prefix = "Info: ";
    static const std::string s_error_prefix = "Error: ";

    enum class Status
    {
        Info,
        Warning,
        Error,
    };

    enum class ErrorId : std::uint32_t
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
        EdlCommentEndingNotFound,
        EdlStringEndingNotFound,
        EdlUnexpectedToken,
        EdlFailureToLoadFile
    };

    struct ErrorIdHash
    {
        std::size_t operator()(ErrorId e) const
        {
            return std::hash<std::uint32_t>()(static_cast<std::uint32_t>(e));
        }
    };

    // When updating these make sure you update ErrorHelpersTests.cpp as well.
    static const std::unordered_map<ErrorId, std::string, ErrorIdHash> c_error_messages =
    {
        // Command line parsing errors
        { ErrorId::LanguageNoMoreArgs,"Unable to find codegen language of choice. No more commandline arguments available to find supported language." },
        { ErrorId::UnsupportedLanguage,"Language '{}' is not supported." },
        { ErrorId::EdlNoMoreArgs,"Unable to find edl file path. No more commandline arguments available to find edl path." },
        { ErrorId::EdlDoesNotExist,"The path to the provided .edl file '{}' does not exist." },
        { ErrorId::NotAnEdlFile,"The path '{}' must be a path to a .edl file." },
        { ErrorId::OutputDirNoMoreArgs,"Unable to find output directory. No more commandline arguments available to find output directory." },
        { ErrorId::OutputDirNotADirectory,"The path '{}' must be a directory that exists. Error code : '{}'" },
        { ErrorId::ErrorHandlingNoMoreArgs,"Unable to find error handling argument. No more commandline arguments available." },
        { ErrorId::ErrorHandlingInvalidType,"Error handling type '{}' invalid." },
        { ErrorId::InvalidArgument,"Unknown argument: {}" },
        { ErrorId::IncorrectNonHelpArgsProvided,"VbsEnclaveTooling.exe expects '{}' arguments when '-h' is not used. Only found: '{}'" },
        { ErrorId::MissingArgument,"Missing arguments. Use '-h' for usage." },

        // Edl file lexical analysis errors
        { ErrorId::EdlCommentEndingNotFound, "EOF while looking for '*/' to match the '/*'" },
        { ErrorId::EdlStringEndingNotFound, "Could not find ending '\"' for string" },
        { ErrorId::EdlUnexpectedToken, "Unexpected token starting with '{}'" },
        { ErrorId::EdlFailureToLoadFile, "Unable to load '{}'" },
    };

    template<typename... Args>
    static std::string inline GetErrorMessageById(ErrorId id, Args&&... args)
    {
        // format the error and its arguments
        auto& message = c_error_messages.at(id);
        return std::vformat(message, std::make_format_args(args...));
    }

    static void inline PrintStatus(const Status& status, const std::string& message)
    {
        if (status == Status::Info)
        {
            std::cout << s_info_prefix + message << std::endl;
        }
        else if (status == Status::Warning)
        {
            std::cout << s_warning_prefix + message << std::endl;
        }
        else
        {
            std::cerr << s_error_prefix + message << std::endl;
        }
    }

    template<typename... Args>
    static void inline PrintError(ErrorId id, Args&&... args)
    {
        if (!(c_error_messages.contains(id)))
        {
            std::cerr << "Invalid error ID: " << static_cast<uint32_t>(id) << std::endl;
            return;
        }

        // format the error and its arguments
        PrintStatus(Status::Error, GetErrorMessageById(id, std::forward<Args>(args)...));
    }
}
