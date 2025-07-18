// Copyright(c) Microsoft Corporation.
// Licensed under the MIT License.

#include <pch.h>
#include "CppUnitTest.h"
#include <CmdlineParsingHelpers.h>
#include <Edl\LexicalAnalyzer.h>
#include <Edl\Utils.h>
#include <unordered_set>
#include <Exceptions.h>
#include "EdlParserTestHelpers.h"

using namespace ErrorHelpers;
using namespace ToolingExceptions;
using namespace EdlProcessor;
using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace VbsEnclaveToolingTests
{

TEST_CLASS(LexicalAnalyzerTests)
{
    private:
        std::filesystem::path m_array_edl_file_name = "ArrayTest.edl";
        std::filesystem::path m_basic_edl_file_name = "BasicTypesTest.edl";
        std::filesystem::path m_enum_edl_file_name = "EnumTest.edl";
        std::filesystem::path m_struct_edl_file_name = "StructTest.edl";
        std::unordered_set<char> m_valid_char_tokens =
        {
            RIGHT_CURLY_BRACKET,
            LEFT_CURLY_BRACKET,
            RIGHT_ROUND_BRACKET,
            LEFT_ROUND_BRACKET,
            RIGHT_SQUARE_BRACKET,
            LEFT_SQUARE_BRACKET,
            RIGHT_ARROW_BRACKET,
            LEFT_ARROW_BRACKET,
            EQUAL_SIGN,
            SEMI_COLON,
            COMMA,
            FORWARD_SLASH,
            ASTERISK,
            DOUBLE_QUOTE,
            END_OF_FILE_CHARACTER,
        };

        bool IsValidToken(const Token& token)
        {

            // Check that token is either identifier, unsigned integer or start of a hexidecimal
            if (token.IsIdentifier() || token.IsUnsignedInteger() || IsHexPrefix(token.m_starting_character))
            {
                return true;
            }

            // Check if its a string literal
            if (token.m_starting_character[0] == DOUBLE_QUOTE && token.m_ending_character[0] == DOUBLE_QUOTE)
            {
                return true;
            }

            // Check if its the end of file character
            if (token.IsEof())
            {
                return true;
            }

            // Check if token is any of the valid edl characters
            if (m_valid_char_tokens.contains(token.m_starting_character[0]))
            {
                return true;
            }

            return false;
        }

        void TokenizeFile(std::filesystem::path file_name)
        {
            try
            {
                // Arrange
                auto analyzer = LexicalAnalyzer(file_name);
                Token token = analyzer.GetNextToken();

                // We should be able to tokenize the entire file without exceptions
                while (!token.IsEmpty())
                {
                    if (!IsValidToken(token))
                    {
                        throw EdlAnalysisException(
                            ErrorId::EdlUnexpectedToken,
                            file_name,
                            token.m_line_number,
                            token.m_column_number,
                            token.ToString());
                    }

                    token = analyzer.GetNextToken();
                }
            }
            catch (const std::exception& exception)
            {
                auto error_message = ConvertExceptionMessageToWstring(exception);
                Assert::Fail(error_message.c_str());
            }
        }

    public:


    TEST_METHOD(TestTokenizingEdlFileThatContainsArrayTypes)
    {
        TokenizeFile(m_array_edl_file_name);
    }

    TEST_METHOD(TestTokenizingEdlFileThatContainsOnlyBasicTypes)
    {
        TokenizeFile(m_basic_edl_file_name);
    }

    TEST_METHOD(TestTokenizingEdlFileThatContainsEnumTypes)
    {
        TokenizeFile(m_enum_edl_file_name);
    }

    TEST_METHOD(TestTokenizingEdlFileThatContainsStructTypes)
    {
        TokenizeFile(m_struct_edl_file_name);
    }    
};
}
