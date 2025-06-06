// Copyright(c) Microsoft Corporation.
// Licensed under the MIT License.

#include <pch.h>
#include <CmdlineParsingHelpers.h>
#include <CmdlineArgumentsParser.h>
#include "CppUnitTest.h"

using namespace CmdlineParsingHelpers;
using namespace Microsoft::VisualStudio::CppUnitTestFramework;

const std::string c_edl_path_valid_input = "BasicTypesTest.edl";

namespace VbsEnclaveToolingTests
{
    TEST_CLASS(CmdlineArgumentsParserTests)
    {
    private:
        std::string m_exe_name = "vbsenclavetooling.exe";
        std::string m_help_args[2] = { "-h", "--help" };
        std::string m_invalid_arg = "--Invalid";
        std::string m_lang_arg = "--Language";
        std::string m_lang_valid_input = "C++";
        std::string m_edl_path_arg = "--EdlPath";
        std::string m_out_dir_arg = "--OutputDirectory";
        std::string m_out_dir_valid_input = ".";
        std::string m_error_handling_arg = "--ErrorHandling";
        std::string m_error_handling_valid_input[2] = { "ErrorCode", "Exception" };
    public:

        // Test valid parsing for known arguments
        TEST_METHOD(TestValidArguments)
        {
            // Simulate command line arguments
            const char* argv[] =
            {
                m_exe_name.data(),
                m_lang_arg.data(),
                m_lang_valid_input.data(),
                m_edl_path_arg.data(),
                c_edl_path_valid_input.data(),
                m_out_dir_arg.data(),
                m_out_dir_valid_input.data(),
                m_error_handling_arg.data(),
                m_error_handling_valid_input[0].data()
            };

            int argc = sizeof(argv) / sizeof(argv[0]);

            // Create an CmdlineArgumentsParser object
            CmdlineArgumentsParser parser(argc, const_cast<char**>(argv));

            // Test if the parser parsed the arguments correctly
            Assert::IsFalse(parser.ShouldDisplayHelp());
            Assert::AreEqual(std::string_view(c_edl_path_valid_input), parser.EdlFilePath());
            Assert::AreEqual(std::string_view(m_out_dir_valid_input), parser.OutDirectory());
            Assert::AreEqual(static_cast<uint32_t>(ErrorHandlingKind::ErrorCode), static_cast<uint32_t>(parser.ErrorHandling()));
            Assert::AreEqual(static_cast<uint32_t>(SupportedLanguageKind::Cpp), static_cast<uint32_t>(parser.SupportedLanguage()));
            Assert::IsTrue(parser.ParseSuccessful());
        }

        // Test for help argument parsing
        TEST_METHOD(TestHelpFlag)
        {
            // Simulate command line arguments with -h and --help argument
            for(auto& helpArg : m_help_args)
            {
                const char* argv[] =
                {
                    m_exe_name.data(),
                    helpArg.data()
                };

                int argc = sizeof(argv) / sizeof(argv[0]);

                // Create an CmdlineArgumentsParser object
                CmdlineArgumentsParser parser(argc,const_cast<char**>(argv));

                // Test if help argument was properly handled
                Assert::IsTrue(parser.ShouldDisplayHelp());
                Assert::IsTrue(parser.ParseSuccessful());
            }
        }

        // Test invalid argument
        TEST_METHOD(TestInvalidArgument)
        {
            // Simulate command line arguments with an unknown argument
            const char* argv[] =
            {
                m_exe_name.data (),
                m_invalid_arg.data (),
                m_lang_valid_input.data ()
            };

            int argc = sizeof (argv) / sizeof (argv[0]);

            // Create an CmdlineArgumentsParser object
            CmdlineArgumentsParser parser(argc, const_cast<char**>(argv));

            // Test if the parser fails due to the invalid argument
            Assert::IsFalse(parser.ParseSuccessful());
        }

        // Test missing argument for a known argument
        TEST_METHOD(TestMissingArgument)
        {
            // Simulate command line arguments missing the input for --Language
            const char* argv[] =
            {
                m_exe_name.data (),
                m_lang_arg.data ()
            };

            int argc = sizeof (argv) / sizeof (argv[0]);

            // Create an CmdlineArgumentsParser object
            CmdlineArgumentsParser parser(argc, const_cast<char**>(argv));

            // Test if the parser fails due to missing input
            Assert::IsFalse(parser.ParseSuccessful());
        }

        // Test parsing failure when no aruments provided
        TEST_METHOD(TestNoArgumentsProvidedToParser)
        {
            // Simulate command line arguments with no arguments
            const char* argv[] =
            {
                m_exe_name.data ()
            };

            int argc = sizeof (argv) / sizeof (argv[0]);
            // Create an CmdlineArgumentsParser object
            CmdlineArgumentsParser parser(argc, const_cast<char**>(argv));

            // Values should all be set to their defaults and parsing should have failed.
            Assert::IsFalse (parser.ShouldDisplayHelp());
            Assert::IsTrue(parser.EdlFilePath().empty());
            Assert::IsTrue(parser.OutDirectory().empty());
            Assert::AreEqual(static_cast<uint32_t>(ErrorHandlingKind::Unknown), static_cast<uint32_t>(parser.ErrorHandling()));
            Assert::AreEqual(static_cast<uint32_t>(SupportedLanguageKind::Unknown), static_cast<uint32_t>(parser.SupportedLanguage()));
            Assert::IsFalse (parser.ParseSuccessful());
        }
    };
}
