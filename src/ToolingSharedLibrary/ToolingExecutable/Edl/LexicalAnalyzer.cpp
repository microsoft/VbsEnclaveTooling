// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
// 
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// This file has been modified and adapted from its original
// which was created by Open Enclave.

#include <pch.h>

#include <Edl\LexicalAnalyzer.h>
#include <Includes\ErrorHelpers.h>
#include <Includes\Exceptions.h>
#include <Edl\Utils.h>

using namespace ErrorHelpers;
using namespace ToolingExceptions;

namespace EdlProcessor
{
    LexicalAnalyzer::LexicalAnalyzer(const std::filesystem::path& file_path)
        : m_file_path(file_path)
    {
    }

    void LexicalAnalyzer::RetrieveAndStoreContentFromEdlFile()
    {
        std::ifstream file(m_file_path.generic_string(), std::ios::in | std::ios::ate);

        if (!file)
        {
            throw EdlAnalysisException(
                ErrorId::EdlFailureToLoadFile,
                m_file_path.filename().generic_string());
        }

        std::streamsize last_character_position = file.tellg();
        file.seekg(0, std::ios::beg);

        // Add an extra null character at the end to symbolize the end of the content.
        std::string file_contents(last_character_position + 1, '\0');
        file.read(&file_contents[0], last_character_position);

        m_file = std::move(file_contents);
        m_null_character_position = &m_file[last_character_position + 1];
        m_line_number = 1;
        m_column_number = 1;
        m_cur_position_character = m_file.c_str();
    }

    bool IsEndOfMultiLineComment(
        const char* starting_character,
        const char* null_character_position)
    {
        const char* next_character = starting_character ? starting_character + 1 : nullptr;

        if (!starting_character || !next_character)
        {
            return true;
        }

        if (starting_character + 1 >= null_character_position)
        {
            return true;
        }

        return starting_character[0] == ASTERISK && next_character[0] == FORWARD_SLASH;
    }

    bool IsEndOfSingleLineComment(const char* cur_position_character)
    {
        if (cur_position_character)
        {
            return cur_position_character[0] == NEW_LINE_CHARACTER;
        }

        return false;
    }

    void LexicalAnalyzer::SkipWhiteSpaceAndComments()
    {
        while (m_cur_position_character < m_null_character_position)
        {
            switch (m_cur_position_character[0])
            {
                case HORIZONTAL_TAB:
                {
                    m_column_number += 4; // Treat Tabs as 4 characters
                    ++m_cur_position_character;
                    continue;
                }
                case WHITE_SPACE:
                {
                    m_column_number++;
                    ++m_cur_position_character;
                    continue;
                }
                case NEW_LINE_CHARACTER:
                {
                    m_line_number++;
                    m_column_number = 1; // Reset column to first position
                    ++m_cur_position_character;
                    continue;
                }
                case CARRIAGE_RETURN:
                case BACKSPACE:
                case VERTICAL_TAB:
                {
                    ++m_cur_position_character;
                    continue;
                }
            }

            // Move past comments
            if (m_cur_position_character[0] == FORWARD_SLASH &&
                m_cur_position_character + 1 < m_null_character_position)
            {
                if (m_cur_position_character[1] == FORWARD_SLASH)
                {
                    // skip past single line comment.
                    while (!IsEndOfSingleLineComment(m_cur_position_character))
                    {
                        ++m_cur_position_character;
                    }

                    continue;
                }

                // Skip past multi-line comment.
                if (m_cur_position_character[1] == ASTERISK)
                {
                    auto start_col_num = m_column_number;
                    auto start_line_num = m_line_number;

                    // move past start of /*
                    m_cur_position_character += 2; 

                    while (!IsEndOfMultiLineComment(m_cur_position_character, m_null_character_position))
                    {
                        ++m_column_number;

                        if (m_cur_position_character[0] == NEW_LINE_CHARACTER)
                        {
                            m_line_number++;
                            m_column_number = 1;
                        }

                        ++m_cur_position_character;
                    }

                    if (m_cur_position_character + 1 >= m_null_character_position)
                    {
                        throw EdlAnalysisException(
                            ErrorId::EdlCommentEndingNotFound,
                            m_file_path.filename().generic_string(),
                            start_line_num,
                            start_col_num);
                    }

                    // Move past */
                    m_cur_position_character += 2; 
                    continue;
                }
            }
            break;
        }
    }

    bool IsStartOfIdentifier(char starting_character)
    {
        return std::isalpha(starting_character) || starting_character == UNDERSCORE;
    }

    bool IsEndOfStringLiteral(const char* start_of_string)
    {
        if (start_of_string)
        {
            return start_of_string[0] == DOUBLE_QUOTE || start_of_string[0] == NEW_LINE_CHARACTER;
        }
        
        return false;
    }

    Token LexicalAnalyzer::GetNextToken()
    {
        if (!m_file_contents_loaded)
        {
            RetrieveAndStoreContentFromEdlFile();
            m_file_contents_loaded = true;
        }

        SkipWhiteSpaceAndComments();

        switch (m_cur_position_character[0])
        {
            case RIGHT_CURLY_BRACKET:
            case LEFT_CURLY_BRACKET:
            case LEFT_ROUND_BRACKET:
            case RIGHT_ROUND_BRACKET:
            case LEFT_SQUARE_BRACKET:
            case RIGHT_SQUARE_BRACKET:
            case RIGHT_ARROW_BRACKET:
            case LEFT_ARROW_BRACKET:
            case ASTERISK:
            case COMMA:
            case SEMI_COLON:
            case EQUAL_SIGN:
            {
                // Tokenize special structural characters 
                auto token = Token(
                    m_line_number,
                    m_column_number,
                    m_cur_position_character,
                    m_cur_position_character + 1);

                m_cur_position_character++;
                m_column_number++;
                return token;
            }
            case END_OF_FILE_CHARACTER: // Should be the end of the file
            {
                auto token = Token(
                    m_line_number,
                    m_column_number,
                    m_cur_position_character,
                    m_cur_position_character);

                return token;
            }
        }

        // Tokenize the name of an identifier e.g a struct field name or a hexidecimal value in an enum.
        // Keywords like "enclave", "struct", "enum", and types like "uint32_t" are also tokenized as
        // identifiers.
        if (IsStartOfIdentifier(m_cur_position_character[0]) || IsHexPrefix(m_cur_position_character))
        {
            auto token = Token(
                m_line_number,
                m_column_number,
                m_cur_position_character,
                m_cur_position_character + 1);

            while (isalnum(m_cur_position_character[0]) || (m_cur_position_character[0] == UNDERSCORE))
            {
                m_cur_position_character++;
            }

            token.m_ending_character = m_cur_position_character;
            m_column_number += static_cast<uint32_t>(m_cur_position_character - token.m_starting_character);
            return token;
        }

        // Tokenize integer literals
        if (std::isdigit(m_cur_position_character[0]))
        {
            auto token = Token(
                m_line_number,
                m_column_number,
                m_cur_position_character,
                m_cur_position_character + 1);

            while (isdigit(m_cur_position_character[0]))
            {
                m_cur_position_character++;
            }

            token.m_ending_character = m_cur_position_character;
            m_column_number += static_cast<uint32_t>(m_cur_position_character - token.m_starting_character);
            return token;
        }

        // Tokenize string literals
        if (m_cur_position_character[0] == DOUBLE_QUOTE)
        {
            auto token = Token(
                m_line_number,
                m_column_number,
                m_cur_position_character,
                m_cur_position_character + 1);

            ++m_cur_position_character;

            while (!IsEndOfStringLiteral(m_cur_position_character))
            {
                ++m_cur_position_character;
            }

            if (m_cur_position_character[0] != DOUBLE_QUOTE)
            {
                throw EdlAnalysisException(
                    ErrorId::EdlStringEndingNotFound,
                    m_file_path.filename().generic_string(),
                    m_line_number,
                    m_column_number);
            }

            token.m_ending_character = ++m_cur_position_character;
            m_column_number += static_cast<uint32_t>(m_cur_position_character - token.m_starting_character);
            return token;
        }

        // If we get here then what we're currently looking at is a token we don't support within 
        // .edl files.
        throw EdlAnalysisException(
            ErrorId::EdlUnexpectedToken,
            m_file_path.filename().generic_string(),
            m_line_number,
            m_column_number,
            m_cur_position_character[0]);
    }
}
