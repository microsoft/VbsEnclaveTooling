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
        std::string m_regular_txt_file = "Edl.txt";
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
            ErrorId result = GetSupportedLanguageForCodeGen(m_starting_index, args, m_args_size, supported_language);

            // Check that the correct language was set
            Assert::AreEqual(static_cast<uint32_t>(ErrorId::Success), static_cast<uint32_t>(result));
            Assert::AreEqual(static_cast<uint32_t>(SupportedLanguageKind::Cpp), static_cast<uint32_t>(supported_language));
        }

        TEST_METHOD(TestGetSupportedLanguageForCodeGen_Invalid)
        {
            char* args[2] = {first_argument.data(),m_invalidLang.data()};
            SupportedLanguageKind supported_language;

            // Call function
            ErrorId result = GetSupportedLanguageForCodeGen(m_starting_index, args, m_args_size, supported_language);

            // Check that the correct error was set and supported_language variable still has default unknown enum value.
            Assert::AreEqual(static_cast<uint32_t>(ErrorId::UnsupportedLanguage), static_cast<uint32_t>(result));
            Assert::AreEqual(static_cast<uint32_t>(SupportedLanguageKind::Unknown), static_cast<uint32_t>(supported_language));
        }

        TEST_METHOD(TestGetEdlPathFromArgs_FileExists)
        {
            char* args[2] = {first_argument.data(), m_test_edl.data()};
            std::string edl_path;

            // Create a mock file(make sure to clean it up if testing in actual file system)
            std::ofstream file(m_test_edl);
            file.close();

            // Call function
            ErrorId result = GetEdlPathFromArgs(m_starting_index, args, m_args_size, edl_path);

            // Check that the file exists.
            Assert::AreEqual(static_cast<uint32_t>(ErrorId::Success), static_cast<uint32_t>(result));
            Assert::AreEqual(m_test_edl, edl_path);

            // Cleanup the mock file
            std::filesystem::remove(m_test_edl);
        }

        TEST_METHOD(TestGetEdlPathFromArgs_NotAnEdlFile)
        {
            char* args[2] = {first_argument.data(), m_regular_txt_file.data()};
            std::string edl_path;

            // Create a mock file(make sure to clean it up if testing in actual file system)
            std::ofstream file(m_regular_txt_file);
            file.close();

            // Call function
            ErrorId result = GetEdlPathFromArgs(m_starting_index, args, m_args_size, edl_path);

            // Make sure edl_path variable hasn't been updated.
            Assert::AreEqual(static_cast<uint32_t>(ErrorId::NotAnEdlFile), static_cast<uint32_t>(result));
            Assert::AreEqual(std::string(""), edl_path);

            // Cleanup the mock file
            std::filesystem::remove(m_regular_txt_file);
        }

        TEST_METHOD(TestGetEdlPathFromArgs_FileDoesNotExist)
        {
            char* args[2] = {first_argument.data(), m_regular_txt_file.data()};
            std::string edl_path;

            // Call function
            ErrorId result = GetEdlPathFromArgs(m_starting_index, args, m_args_size, edl_path);

            // Check that the file does not exist and that the edl_path_variable hasn't been changed.
            Assert::AreEqual(static_cast<uint32_t>(ErrorId::EdlDoesNotExist), static_cast<uint32_t>(result));
            Assert::AreEqual(std::string(""), edl_path);
        }

        TEST_METHOD(TestGetPathToOutputDirectoryFromArgs_Valid)
        {
            char* args[2] = {first_argument.data(), m_cur_directory.data()};
            std::string directory;

            // Call function
            ErrorId result = GetPathToOutputDirectoryFromArgs(m_starting_index, args, m_args_size, directory);

            // Check that the directory was correctly set
            Assert::AreEqual(static_cast<uint32_t>(ErrorId::Success), static_cast<uint32_t>(result));
            Assert::AreEqual(std::string("."), directory);
        }

        TEST_METHOD(TestGetPathToOutputDirectoryFromArgs_Invalid)
        {
            char* args[2] = {first_argument.data(), m_invalid_directory.data()};
            std::string directory;

            // Call function
            ErrorId result = GetPathToOutputDirectoryFromArgs(m_starting_index, args, m_args_size, directory);

            // Check that the directory is still empty and an error was returned.
            Assert::AreEqual(static_cast<uint32_t>(ErrorId::OutputDirNotADirectory), static_cast<uint32_t>(result));
            Assert::AreEqual(std::string(""), directory);
        }

        TEST_METHOD(TestGetErrorHandlingFromArg_Valid_ErrorCodeType)
        {
            char* args[2] = {first_argument.data(), m_valid_Error_types[0].data()};
            ErrorHandlingKind errorKind;

            // Call function
            ErrorId result = GetErrorHandlingFromArg(m_starting_index, args, m_args_size, errorKind);

            // Check that the error kind was correctly set
            Assert::AreEqual(static_cast<uint32_t>(ErrorId::Success), static_cast<uint32_t>(result));
            Assert::AreEqual(static_cast<uint32_t>(ErrorHandlingKind::ErrorCode), static_cast<uint32_t>(errorKind));
        }

        TEST_METHOD(TestGetErrorHandlingFromArg_Valid_ExceptionType)
        {
            char* args[2] = {first_argument.data(), m_valid_Error_types[1].data()};
            ErrorHandlingKind errorKind;

            // Call function
            ErrorId result = GetErrorHandlingFromArg(m_starting_index, args, m_args_size, errorKind);

            // Check that the error kind was correctly set
            Assert::AreEqual(static_cast<uint32_t>(ErrorId::Success), static_cast<uint32_t>(result));
            Assert::AreEqual(static_cast<uint32_t>(ErrorHandlingKind::Exception), static_cast<uint32_t>(errorKind));
        }

        TEST_METHOD(TestGetErrorHandlingFromArg_InvalidType)
        {
            char* args[2] = {first_argument.data(), m_invalid_Error_type.data()};
            ErrorHandlingKind errorKind;

            // Call function
            ErrorId result = GetErrorHandlingFromArg(m_starting_index, args, m_args_size, errorKind);

            // Check that the error kind was not changed
            Assert::AreEqual(static_cast<uint32_t>(ErrorId::ErrorHandlingInvalidType), static_cast<uint32_t>(result));
            Assert::AreEqual(static_cast<uint32_t>(ErrorHandlingKind::Unknown), static_cast<uint32_t>(errorKind));
        }

        TEST_METHOD(TestGetSupportedLanguageForCodeGen_OutOfBounds)
        {
            char* args[2] = {first_argument.data(),m_validLang.data()};
            SupportedLanguageKind supported_language;

            // Call function
            ErrorId result = GetSupportedLanguageForCodeGen(m_invalid_starting_index, args, m_args_size, supported_language);

            // Check that no more args result was returned and out param still the same
            Assert::AreEqual(static_cast<uint32_t>(ErrorId::LanguageNoMoreArgs), static_cast<uint32_t>(result));
            Assert::AreEqual(static_cast<uint32_t>(SupportedLanguageKind::Unknown), static_cast<uint32_t>(supported_language));
        }

        TEST_METHOD(TestGetEdlPathFromArgs_OutOfBounds)
        {
            char* args[2] = {first_argument.data(), m_test_edl.data()};
            std::string edl_path;

            // Call function
            ErrorId result = GetEdlPathFromArgs(m_invalid_starting_index, args, m_args_size, edl_path);

            // Check that no more args result was returned and out param still the same
            Assert::AreEqual(static_cast<uint32_t>(ErrorId::EdlNoMoreArgs), static_cast<uint32_t>(result));
            Assert::AreEqual(std::string(""), edl_path);
        }

        TEST_METHOD(TestGetErrorHandlingFromArg_OutOfBounds)
        {
            char* args[2] = {first_argument.data(), m_valid_Error_types[0].data()};
            ErrorHandlingKind errorKind;

            // Call function
            ErrorId result = GetErrorHandlingFromArg(m_invalid_starting_index, args, m_args_size, errorKind);

            // Check that no more args result was returned and out param still the same
            Assert::AreEqual(static_cast<uint32_t>(ErrorId::ErrorHandlingNoMoreArgs), static_cast<uint32_t>(result));
            Assert::AreEqual(static_cast<uint32_t>(ErrorHandlingKind::Unknown), static_cast<uint32_t>(errorKind));
        }

        TEST_METHOD(TestGetPathToOutputDirectoryFromArgs_OutOfBounds)
        {
            char* args[2] = {first_argument.data(), m_cur_directory.data()};
            std::string directory;

            // Call function
            ErrorId result = GetPathToOutputDirectoryFromArgs(m_invalid_starting_index, args, m_args_size, directory);

            // Check that no more args result was returned and out param still the same
            Assert::AreEqual(static_cast<uint32_t>(ErrorId::OutputDirNoMoreArgs), static_cast<uint32_t>(result));
            Assert::AreEqual(std::string(""), directory);
        }
    };
}
