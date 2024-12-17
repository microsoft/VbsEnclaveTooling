// Copyright(c) Microsoft Corporation.
// Licensed under the MIT License.

#include <pch.h>
#include "CppUnitTest.h"
#include <CmdlineParsingHelpers.h>

using namespace CmdlineParsingHelpers;
using namespace ErrorHelpers;
using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace VbsEnclaveToolingTests
{

TEST_CLASS(CmdlineParsingHelpersTests)
    {
    private:
        std::uint32_t m_starting_index = 1;
        std::uint32_t m_invalid_starting_index = 3;
        std::uint32_t m_args_size = 2;

        // This value is unimportant but symbolizes an argument like "--EdlPath" in the space delimited argument
        // array on the commandline e.g "--EdlPath C:\test.edl". For these tests we only care about the second 
        // argument, which in the above case would be 'C:\test.edl'
        std::string first_argument = "--Arg";
        std::string m_validLang = "C++";
        std::string m_invalidLang = "java";
        std::string m_test_edl = "test.edl";
        std::string m_invalid_test_edl = "InvalidEdl.txt";
        std::string m_cur_directory = ".";
        std::string m_invalid_directory = "C:\\dir\\does\\?not?exist";
        std::string m_valid_Error_types[2] = { "ErrorCode", "Exception" };
        std::string m_invalid_Error_type = "InvalidErrorType";

    public:
        TEST_METHOD(TestGetSupportedLanguageForCodeGen_Valid)
        {
            char* args[2] = {first_argument.data(),m_validLang.data()};
            SupportedLanguageKind supported_language;

            // Call function
            Assert::IsTrue(GetSupportedLanguageForCodeGen(m_starting_index, args, m_args_size, supported_language));

            // Check that the correct language was set
            Assert::AreEqual(static_cast<uint32_t>(SupportedLanguageKind::Cpp), static_cast<uint32_t>(supported_language));
        }

        TEST_METHOD(TestGetSupportedLanguageForCodeGen_Invalid)
        {
            char* args[2] = { first_argument.data(),m_invalidLang.data() };
            SupportedLanguageKind supported_language;

            // Call function
            Assert::IsFalse(GetSupportedLanguageForCodeGen(m_starting_index, args, m_args_size, supported_language));
            Assert::AreEqual(static_cast<uint32_t>(SupportedLanguageKind::Unknown), static_cast<uint32_t>(supported_language));
        }

        TEST_METHOD(TestGetEdlPathFromArgs_Valid)
        {
            char* args[2] = { first_argument.data(),m_test_edl.data() };
            std::string edl_path;

            // Create a mock file(make sure to clean it up if testing in actual file system)
            std::ofstream file(m_test_edl);
            file.close();

            // Call function
            Assert::IsTrue(GetEdlPathFromArgs(m_starting_index, args, m_args_size, edl_path));

            // Check that the path was correctly set
            Assert::AreEqual(m_test_edl, edl_path);

            // Cleanup the mock file
            std::filesystem::remove(m_test_edl);
        }

        TEST_METHOD(TestGetEdlPathFromArgs_Invalid)
        {
            char* args[2] = { first_argument.data(), m_invalid_test_edl.data() };
            std::string edl_path;

            // Call function
            Assert::IsFalse(GetEdlPathFromArgs(m_starting_index, args, m_args_size, edl_path));
            Assert::AreNotEqual(m_invalid_test_edl, edl_path);
        }

        TEST_METHOD(TestGetPathToOutputDirectoryFromArgs_Valid)
        {
            char* args[2] = { first_argument.data(), m_cur_directory.data() };
            std::string directory;

            // Call function
            Assert::IsTrue(GetPathToOutputDirectoryFromArgs(m_starting_index, args, m_args_size, directory));
            // Check that the directory was correctly set
            Assert::AreEqual(std::string("."), directory);
        }

        TEST_METHOD(TestGetPathToOutputDirectoryFromArgs_Invalid)
        {
            char* args[2] = { first_argument.data(), m_invalid_directory.data() };
            std::string directory;

            // Call function
            Assert::IsFalse(GetPathToOutputDirectoryFromArgs(m_starting_index, args, m_args_size, directory));

            // Check that the directory was correctly set
            Assert::AreEqual(std::string(), directory);
        }

        TEST_METHOD(TestGetErrorHandlingFromArg_Valid_ErrorCodeType)
        {
            char* args[2] = { first_argument.data(), m_valid_Error_types[0].data() };
            ErrorHandlingKind errorKind;

            // Call function
            Assert::IsTrue(GetErrorHandlingFromArg(m_starting_index, args, m_args_size, errorKind));

            // Check that the error kind was correctly set
            Assert::AreEqual(static_cast<uint32_t>(ErrorHandlingKind::ErrorCode), static_cast<uint32_t>(errorKind));
        }

        TEST_METHOD(TestGetErrorHandlingFromArg_Valid_ExceptionType)
        {
            char* args[2] = { first_argument.data(), m_valid_Error_types[1].data() };
            ErrorHandlingKind errorKind;

            // Call function
            Assert::IsTrue(GetErrorHandlingFromArg(m_starting_index, args, m_args_size, errorKind));

            // Check that the error kind was correctly set
            Assert::AreEqual(static_cast<uint32_t>(ErrorHandlingKind::Exception), static_cast<uint32_t>(errorKind));
        }

        TEST_METHOD(TestGetErrorHandlingFromArg_InvalidType)
        {
            char* args[2] = { first_argument.data(), m_invalid_Error_type.data() };
            ErrorHandlingKind errorKind;

            // Call function
            Assert::IsFalse(GetErrorHandlingFromArg(m_starting_index, args, m_args_size, errorKind));
            Assert::AreEqual(static_cast<uint32_t>(ErrorHandlingKind::Unknown), static_cast<uint32_t>(errorKind));
        }

        TEST_METHOD(TestGetSupportedLanguageForCodeGen_OutOfBounds)
        {
            char* args[2] = { first_argument.data(),m_validLang.data() };
            SupportedLanguageKind supported_language;

            // Call function
            Assert::IsFalse(GetSupportedLanguageForCodeGen(m_invalid_starting_index, args, m_args_size, supported_language));
            Assert::AreEqual(static_cast<uint32_t>(SupportedLanguageKind::Unknown), static_cast<uint32_t>(supported_language));
        }

        TEST_METHOD(TestGetEdlPathFromArgs_OutOfBounds)
        {
            char* args[2] = { first_argument.data(),m_test_edl.data() };
            std::string edl_path;

            // Call function
            Assert::IsFalse(GetEdlPathFromArgs(m_invalid_starting_index, args, m_args_size, edl_path));
            Assert::AreNotEqual(m_invalid_test_edl, edl_path);
        }

        TEST_METHOD(TestGetErrorHandlingFromArg_OutOfBounds)
        {
            char* args[2] = { first_argument.data(), m_valid_Error_types[0].data() };
            ErrorHandlingKind errorKind;

            // Call function
            Assert::IsFalse(GetErrorHandlingFromArg(m_invalid_starting_index, args, m_args_size, errorKind));
            Assert::AreEqual(static_cast<uint32_t>(ErrorHandlingKind::Unknown), static_cast<uint32_t>(errorKind));
        }

        TEST_METHOD(TestGetPathToOutputDirectoryFromArgs_OutOfBounds)
        {
            char* args[2] = { first_argument.data(), m_cur_directory.data() };
            std::string directory;

            // Call function
            Assert::IsFalse(GetPathToOutputDirectoryFromArgs(m_invalid_starting_index, args, m_args_size, directory));

            // Check that the directory was correctly set
            Assert::AreEqual(std::string(), directory);
        }
    };
}
