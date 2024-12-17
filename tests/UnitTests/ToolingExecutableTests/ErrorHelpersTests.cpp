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
        std::unordered_map<ErrorIds, std::string, ErrorIdsHash> m_test_error_messages =
        {
           { ErrorIds::LanguageNoMoreArgs, "Unable to find codegen language of choice. No more commandline arguments available to find supported language.\n" },
           { ErrorIds::UnsupportedLanguage, "Language '{}' is not supported.\n" },
           { ErrorIds::EdlNoMoreArgs, "Unable to find edl file path. No more commandline arguments available to find edl path.\n" },
           { ErrorIds::EdlDoesNotExist, "The path to the provided .edl file '{}' does not exist.\n" },
           { ErrorIds::NotAnEdlFile, "The path '{}' must be a path to a .edl file.\n" },
           { ErrorIds::OutputDirNoMoreArgs, "Unable to find output directory. No more commandline arguments available to find output directory.\n" },
           { ErrorIds::OutputDirNotADirectory, "The path '{}' must be a directory that exists. Error code : '{}'\n" },
           { ErrorIds::ErrorHandlingNoMoreArgs, "Unable to find error handling argument. No more commandline arguments available.\n" },
           { ErrorIds::ErrorHandlingInvalidType, "Error handling type '{}' invalid.\n" },
           { ErrorIds::InvalidArgument, "Unknown argument: {}\n" },
           { ErrorIds::IncorrectNonHelpArgsProvided, "VbsEnclaveTooling.exe expects '{}' arguments when '-h' is not used. Only found: '{}'\n" },
           { ErrorIds::MissingArgument, "Missing arguments. Use '-h' for usage.\n" }
        };

        TEST_METHOD(TestPrintLanguageNoMoreArgs)
        {
            RedirectCerr redirect_cerr;
            std::string expected_msg = m_test_error_messages.at(ErrorIds::LanguageNoMoreArgs);
            PrintError(ErrorIds::LanguageNoMoreArgs);
            Assert::AreEqual(expected_msg, redirect_cerr.GetString());
        }

        TEST_METHOD(TestPrintUnsupportedLanguage)
        {
            RedirectCerr redirect_cerr;
            std::string expected_msg = m_test_error_messages.at(ErrorIds::UnsupportedLanguage);
            expected_msg = std::vformat(expected_msg, std::make_format_args(m_invalid_lang));
            PrintError(ErrorIds::UnsupportedLanguage, m_invalid_lang);
            Assert::AreEqual(expected_msg, redirect_cerr.GetString());
        }

        TEST_METHOD(TestPrintEdlNoMoreArgs)
        {
            RedirectCerr redirect_cerr;
            std::string expected_msg = m_test_error_messages.at(ErrorIds::EdlNoMoreArgs);
            PrintError(ErrorIds::EdlNoMoreArgs);
            Assert::AreEqual(expected_msg, redirect_cerr.GetString());
        }

        TEST_METHOD(TestPrintEdlDoesNotExist)
        {
            RedirectCerr redirect_cerr;
            std::string expected_msg = m_test_error_messages.at(ErrorIds::EdlDoesNotExist);
            expected_msg = std::vformat(expected_msg, std::make_format_args(m_edl_invalid_path));
            PrintError(ErrorIds::EdlDoesNotExist, m_edl_invalid_path);
            Assert::AreEqual(expected_msg, redirect_cerr.GetString());
        }

        TEST_METHOD(TestPrintNotAnEdlFile)
        {
            RedirectCerr redirect_cerr;
            std::string expected_msg = m_test_error_messages.at(ErrorIds::NotAnEdlFile);
            expected_msg = std::vformat(expected_msg, std::make_format_args(m_edl_invalid_file));
            PrintError(ErrorIds::NotAnEdlFile, m_edl_invalid_file);
            Assert::AreEqual(expected_msg, redirect_cerr.GetString());
        }

        TEST_METHOD(TestPrintOutputDirNoMoreArgs)
        {
            RedirectCerr redirect_cerr;
            std::string expected_msg = m_test_error_messages.at(ErrorIds::OutputDirNoMoreArgs);
            PrintError(ErrorIds::OutputDirNoMoreArgs);
            Assert::AreEqual(expected_msg, redirect_cerr.GetString());
        }

        TEST_METHOD(TestPrintOutputDirNotADirectory)
        {
            RedirectCerr redirect_cerr;
            std::string expected_msg = m_test_error_messages.at(ErrorIds::OutputDirNotADirectory);
            expected_msg = std::vformat(expected_msg, std::make_format_args(m_out_dir_invalid_path, m_out_dir_error_code));
            PrintError(ErrorIds::OutputDirNotADirectory, m_out_dir_invalid_path, m_out_dir_error_code);
            Assert::AreEqual(expected_msg, redirect_cerr.GetString());
        }

        TEST_METHOD(TestPrintErrorHandlingNoMoreArgs)
        {
            RedirectCerr redirect_cerr;
            std::string expected_msg = m_test_error_messages.at(ErrorIds::ErrorHandlingNoMoreArgs);
            PrintError(ErrorIds::ErrorHandlingNoMoreArgs);
            Assert::AreEqual(expected_msg, redirect_cerr.GetString());
        }

        TEST_METHOD(TestPrintErrorHandlingInvalidType)
        {
            RedirectCerr redirect_cerr;
            std::string expected_msg = m_test_error_messages.at(ErrorIds::ErrorHandlingInvalidType);
            expected_msg = std::vformat(expected_msg, std::make_format_args(m_error_handling_invalid));
            PrintError(ErrorIds::ErrorHandlingInvalidType, m_error_handling_invalid);
            Assert::AreEqual(expected_msg, redirect_cerr.GetString());
        }

        TEST_METHOD(TestPrintInvalidArgument)
        {
            RedirectCerr redirect_cerr;
            std::string expected_msg = m_test_error_messages.at(ErrorIds::InvalidArgument);
            expected_msg = std::vformat(expected_msg, std::make_format_args(m_invalid_arg));
            PrintError(ErrorIds::InvalidArgument, m_invalid_arg);
            Assert::AreEqual(expected_msg, redirect_cerr.GetString());
        }

        TEST_METHOD(TestPrintIncorrectNonHelpArgsProvided)
        {
            RedirectCerr redirect_cerr;
            std::string expected_msg = m_test_error_messages.at(ErrorIds::IncorrectNonHelpArgsProvided);
            expected_msg = std::vformat(expected_msg, std::make_format_args(m_max_args, m_invalid_arg_amount));
            PrintError(ErrorIds::IncorrectNonHelpArgsProvided, m_max_args, m_invalid_arg_amount);
            Assert::AreEqual(expected_msg, redirect_cerr.GetString());
        }

        TEST_METHOD(TestPrintMissingArgument)
        {
            RedirectCerr redirect_cerr;
            std::string expected_msg = m_test_error_messages.at(ErrorIds::MissingArgument);
            PrintError(ErrorIds::MissingArgument);
            Assert::AreEqual(expected_msg, redirect_cerr.GetString());
        }
    };
}
