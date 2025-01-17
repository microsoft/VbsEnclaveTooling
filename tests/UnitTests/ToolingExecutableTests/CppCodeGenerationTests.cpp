// Copyright(c) Microsoft Corporation.
// Licensed under the MIT License.

#include <pch.h>
#include "CppUnitTest.h"
#include <CmdlineParsingHelpers.h>
#include <Edl\Parser.h>
#include <Edl\Utils.h>
#include <unordered_set>
#include <Exceptions.h>
#include "EdlParserTestHelpers.h"
#include <CodeGeneration\CodeGeneration.h>

using namespace ErrorHelpers;
using namespace ToolingExceptions;
using namespace EdlProcessor;
using namespace CodeGeneration;
using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace VbsEnclaveToolingTests
{

TEST_CLASS(CppCodeGenerationTests)
{
    private:

    std::filesystem::path m_edl_file_path = "DeveloperTypesCodeGen.edl";
    std::filesystem::path m_base_header_path = R"(..\..\..\tests\UnitTests\TestFiles\ExpectedCodeGeneratedFiles\VbsEnclaveBase.h)";
    std::filesystem::path m_developer_types_header_path = R"(..\..\..\tests\UnitTests\TestFiles\ExpectedCodeGeneratedFiles\EnclaveDeveloperTypes.h)";
    static const uint32_t m_cmdline_arg_count = 11;
    const char* m_cmdline_args[m_cmdline_arg_count] =
    {
        "VbsEnclaveTooling.exe",
        "--Language",
        "C++" ,
        "--EdlPath",
        "ExpectedCodeGeneratedFiles/DeveloperTypesCodeGen.edl",
        "--ErrorHandling",
        "ErrorCode",
        "--OutputDirectory",
        ".", // use current directory as output directory
    };

    public:

    std::string TrimNullPaddingAtTheEnd(std::string str)
    {
        size_t lastNullPos = str.find_last_of('\0');

        if (lastNullPos == std::string::npos)
        {
            return str;
        }

        // Remove all null characters that appear at end of string itself.
        std::string result = str.substr(0, lastNullPos);
        result.erase(std::remove(result.begin(), result.end(), '\0'), result.end());

        return result;
    }

    std::string GetTestFileContent(const std::filesystem::path& file_path)
    {
        std::ifstream file(file_path.generic_string(), std::ios::in | std::ios::ate);

        if (!file)
        {
            auto error_str = std::format("Couldn't open test file: '{}'", file_path.generic_string());
            throw std::runtime_error(error_str);
        }

        std::streamsize last_character_position = file.tellg();
        file.seekg(0, std::ios::beg);

        std::string file_contents(last_character_position, '\0');
        std::stringstream ss;

        file.read(&file_contents[0], last_character_position);

        return TrimNullPaddingAtTheEnd(file_contents);
    }

    TEST_METHOD(Generate_EnclaveBase_Header_file)
    {
        try
        {
            auto argument_parser = CmdlineArgumentsParser(m_cmdline_arg_count, const_cast<char**>(m_cmdline_args));
            auto edl_parser = EdlParser(m_edl_file_path);
            Edl edl = edl_parser.Parse();

            auto code_generator = CppCodeGenerator(edl, argument_parser);
            code_generator.Generate();

            // verify contents of base enclave header
            auto expected_content = GetTestFileContent(m_base_header_path);
            auto actual_content = code_generator.EnclaveBaseHeader();
            Assert::AreEqual(expected_content.size(), actual_content.size());
            Assert::AreEqual(std::string_view(expected_content), actual_content);
        }
        catch (const std::exception& exception)
        {
            auto error_message = ConvertExceptionMessageToWstring(exception);
            Assert::Fail(error_message.c_str());
        }
    }

    TEST_METHOD(Generate_DeveloperTypes_Header_file)
    {
        try
        {
            auto argument_parser = CmdlineArgumentsParser(m_cmdline_arg_count, const_cast<char**>(m_cmdline_args));
            auto edl_parser = EdlParser(m_edl_file_path);
            Edl edl = edl_parser.Parse();

            auto code_generator = CppCodeGenerator(edl, argument_parser);
            code_generator.Generate();
            
            // verify contents of generated developer types header
            auto expected_content = GetTestFileContent(m_developer_types_header_path);
            auto actual_content = code_generator.EnclaveTypesHeader();
            Assert::AreEqual(expected_content.size(), actual_content.size());
            Assert::AreEqual(std::string_view(expected_content), actual_content);
        }
        catch (const std::exception& exception)
        {
            auto error_message = ConvertExceptionMessageToWstring(exception);
            Assert::Fail(error_message.c_str());
        }
    }
};
}
