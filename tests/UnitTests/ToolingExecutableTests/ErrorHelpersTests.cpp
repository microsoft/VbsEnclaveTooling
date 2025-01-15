// Copyright(c) Microsoft Corporation.
// Licensed under the MIT License.

#include <pch.h>
#include <CmdlineParsingHelpers.h>
#include <ErrorHelpers.h>
#include "CppUnitTest.h"

using namespace ErrorHelpers;
using namespace Microsoft::VisualStudio::CppUnitTestFramework;

// Redirect std::cerr to a stringstream (for testing output)
class RedirectCerr
{
public:
    RedirectCerr()
    {
        std::cerr.rdbuf(m_captured_output.rdbuf());
    }
    ~RedirectCerr()
    {
        std::cerr.rdbuf(original_cerr);
        m_captured_output.str("");
        m_captured_output.clear();
    }

    std::string GetString()
    {
        return m_captured_output.str();
    }

private:
    std::streambuf* original_cerr = std::cerr.rdbuf();
    std::ostringstream m_captured_output;
};
namespace VbsEnclaveToolingTests
{
    TEST_CLASS(PrintErrorUnitTests)
    {
    private:
        std::string m_error_prefix = "Error: ";
        std::string m_invalid_lang = "java";
        std::string m_edl_invalid_path = "C:\\bad\\path\\to\\edl.edl";
        std::string m_edl_invalid_file = "test.txt";
        std::string m_invalid_arg = "--Invalid";
        std::string m_error_handling_invalid = "Err";
        std::string m_out_dir_invalid_path = "C:\\bad\\path\\to\\directory";
        uint32_t m_out_dir_error_code = 2;
        uint32_t m_max_args = 5;
        uint32_t m_invalid_arg_amount = 3;

    public:
        // Make sure you add a new line character at the end.
        std::unordered_map<ErrorId, std::string, ErrorIdHash> m_test_error_messages =
        {
           { ErrorId::LanguageNoMoreArgs, "Unable to find codegen language of choice. No more commandline arguments available to find supported language.\n" },
           { ErrorId::UnsupportedLanguage, "Language '{}' is not supported.\n" },
           { ErrorId::EdlNoMoreArgs, "Unable to find edl file path. No more commandline arguments available to find edl path.\n" },
           { ErrorId::EdlDoesNotExist, "The path to the provided .edl file '{}' does not exist.\n" },
           { ErrorId::NotAnEdlFile, "The path '{}' must be a path to a .edl file.\n" },
           { ErrorId::OutputDirNoMoreArgs, "Unable to find output directory. No more commandline arguments available to find output directory.\n" },
           { ErrorId::OutputDirNotADirectory, "The path '{}' must be a directory that exists. Error code : '{}'\n" },
           { ErrorId::ErrorHandlingNoMoreArgs, "Unable to find error handling argument. No more commandline arguments available.\n" },
           { ErrorId::ErrorHandlingInvalidType, "Error handling type '{}' invalid.\n" },
           { ErrorId::InvalidArgument, "Unknown argument: {}\n" },
           { ErrorId::IncorrectNonHelpArgsProvided, "VbsEnclaveTooling.exe expects '{}' arguments when '-h' is not used. Only found: '{}'\n" },
           { ErrorId::MissingArgument, "Missing arguments. Use '-h' for usage.\n" }
        };

        TEST_METHOD(TestPrintLanguageNoMoreArgs)
        {
            RedirectCerr redirect_cerr;
            std::string expected_msg = m_error_prefix + m_test_error_messages.at(ErrorId::LanguageNoMoreArgs);
            PrintError(ErrorId::LanguageNoMoreArgs);
            Assert::AreEqual(expected_msg, redirect_cerr.GetString());
        }

        TEST_METHOD(TestPrintUnsupportedLanguage)
        {
            RedirectCerr redirect_cerr;
            std::string expected_msg = m_error_prefix + m_test_error_messages.at(ErrorId::UnsupportedLanguage);
            expected_msg = std::vformat(expected_msg, std::make_format_args(m_invalid_lang));
            PrintError(ErrorId::UnsupportedLanguage, m_invalid_lang);
            Assert::AreEqual(expected_msg, redirect_cerr.GetString());
        }

        TEST_METHOD(TestPrintEdlNoMoreArgs)
        {
            RedirectCerr redirect_cerr;
            std::string expected_msg = m_error_prefix + m_test_error_messages.at(ErrorId::EdlNoMoreArgs);
            PrintError(ErrorId::EdlNoMoreArgs);
            Assert::AreEqual(expected_msg, redirect_cerr.GetString());
        }

        TEST_METHOD(TestPrintEdlDoesNotExist)
        {
            RedirectCerr redirect_cerr;
            std::string expected_msg = m_error_prefix + m_test_error_messages.at(ErrorId::EdlDoesNotExist);
            expected_msg = std::vformat(expected_msg, std::make_format_args(m_edl_invalid_path));
            PrintError(ErrorId::EdlDoesNotExist, m_edl_invalid_path);
            Assert::AreEqual(expected_msg, redirect_cerr.GetString());
        }

        TEST_METHOD(TestPrintNotAnEdlFile)
        {
            RedirectCerr redirect_cerr;
            std::string expected_msg = m_error_prefix + m_test_error_messages.at(ErrorId::NotAnEdlFile);
            expected_msg = std::vformat(expected_msg, std::make_format_args(m_edl_invalid_file));
            PrintError(ErrorId::NotAnEdlFile, m_edl_invalid_file);
            Assert::AreEqual(expected_msg, redirect_cerr.GetString());
        }

        TEST_METHOD(TestPrintOutputDirNoMoreArgs)
        {
            RedirectCerr redirect_cerr;
            std::string expected_msg = m_error_prefix + m_test_error_messages.at(ErrorId::OutputDirNoMoreArgs);
            PrintError(ErrorId::OutputDirNoMoreArgs);
            Assert::AreEqual(expected_msg, redirect_cerr.GetString());
        }

        TEST_METHOD(TestPrintOutputDirNotADirectory)
        {
            RedirectCerr redirect_cerr;
            std::string expected_msg = m_error_prefix + m_test_error_messages.at(ErrorId::OutputDirNotADirectory);
            expected_msg = std::vformat(expected_msg, std::make_format_args(m_out_dir_invalid_path, m_out_dir_error_code));
            PrintError(ErrorId::OutputDirNotADirectory, m_out_dir_invalid_path, m_out_dir_error_code);
            Assert::AreEqual(expected_msg, redirect_cerr.GetString());
        }

        TEST_METHOD(TestPrintErrorHandlingNoMoreArgs)
        {
            RedirectCerr redirect_cerr;
            std::string expected_msg = m_error_prefix + m_test_error_messages.at(ErrorId::ErrorHandlingNoMoreArgs);
            PrintError(ErrorId::ErrorHandlingNoMoreArgs);
            Assert::AreEqual(expected_msg, redirect_cerr.GetString());
        }

        TEST_METHOD(TestPrintErrorHandlingInvalidType)
        {
            RedirectCerr redirect_cerr;
            std::string expected_msg = m_error_prefix + m_test_error_messages.at(ErrorId::ErrorHandlingInvalidType);
            expected_msg = std::vformat(expected_msg, std::make_format_args(m_error_handling_invalid));
            PrintError(ErrorId::ErrorHandlingInvalidType, m_error_handling_invalid);
            Assert::AreEqual(expected_msg, redirect_cerr.GetString());
        }

        TEST_METHOD(TestPrintInvalidArgument)
        {
            RedirectCerr redirect_cerr;
            std::string expected_msg = m_error_prefix + m_test_error_messages.at(ErrorId::InvalidArgument);
            expected_msg = std::vformat(expected_msg, std::make_format_args(m_invalid_arg));
            PrintError(ErrorId::InvalidArgument, m_invalid_arg);
            Assert::AreEqual(expected_msg, redirect_cerr.GetString());
        }

        TEST_METHOD(TestPrintIncorrectNonHelpArgsProvided)
        {
            RedirectCerr redirect_cerr;
            std::string expected_msg = m_error_prefix + m_test_error_messages.at(ErrorId::IncorrectNonHelpArgsProvided);
            expected_msg = std::vformat(expected_msg, std::make_format_args(m_max_args, m_invalid_arg_amount));
            PrintError(ErrorId::IncorrectNonHelpArgsProvided, m_max_args, m_invalid_arg_amount);
            Assert::AreEqual(expected_msg, redirect_cerr.GetString());
        }

        TEST_METHOD(TestPrintMissingArgument)
        {
            RedirectCerr redirect_cerr;
            std::string expected_msg = m_error_prefix + m_test_error_messages.at(ErrorId::MissingArgument);
            PrintError(ErrorId::MissingArgument);
            Assert::AreEqual(expected_msg, redirect_cerr.GetString());
        }
    };
}
