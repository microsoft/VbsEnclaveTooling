// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
// 
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// This file has been modified and adapted from its original
// which was created by Open Enclave.

#pragma once
#include <pch.h>

namespace EdlProcessor
{
    struct Token
    {
        Token() = default;

        Token(
            const std::uint32_t& line_number,
            const std::uint32_t& column_number, 
            const char* start,
            const char* end)
                : m_line_number(line_number),
                  m_column_number(column_number),
                  m_starting_character(start),
                  m_ending_character(end)
        {
        }

        std::uint32_t m_line_number {0};
        std::uint32_t m_column_number {0};
        const char* m_starting_character {0};
        const char* m_ending_character {0};

        // Anonymous enums don't have a specific token name/identifier 
        // as they will just show up as '{' because they are declared like:  
        //     enum
        //     {
        //         ...
        //     };
        // 
        // while a regular enum's token e.g:
        // 
        //     enum TestEnum
        //     {
        //         ...
        //     };
        // 
        // will have its Token identifier as 'TestEnum'.
        bool is_anonymous_enum_token {false};

        Token& operator=(const Token& other)
        {
            if (this == &other)  // Check for self-assignment
            {
                return *this;
            }

            m_line_number = other.m_line_number;
            m_column_number = other.m_column_number;
            m_starting_character = other.m_starting_character;
            m_ending_character = other.m_ending_character;

            return *this;
        }

        bool operator==(const char* str) const
        {
            size_t token_len = Length();
            size_t string_len = static_cast<size_t>(strlen(str));
            return (token_len == string_len) && (strncmp(m_starting_character, str, token_len) == 0);
        }

        bool operator!=(const char* str) const
        {
            return !(*this == str);
        }

        bool operator==(const char ch) const
        {
            return m_starting_character[0] == ch;
        }

        bool operator!=(const char ch) const
        {
            return m_starting_character[0] != ch;
        }

        size_t Length() const
        {
            // The length of the EOF character should always be 1.
            if (IsEof())
            {
                return 1;
            }

            return static_cast<size_t>(m_ending_character - m_starting_character);
        }

        bool IsEof() const
        {
            return m_starting_character[0] == '\0';
        }

        bool IsIdentifier() const
        {
            return std::isalpha(m_starting_character[0]) || (m_starting_character[0] == '_');
        }

        bool IsUnsignedInteger() const
        {
            return std::isdigit(m_starting_character[0]);
        }

        bool IsEmpty() const
        {
            return IsEof();
        }

        std::string ToString() const
        {
            return IsEmpty() ? "" : std::string(m_starting_character, m_ending_character);
        }

        static Token CreateEmptyToken()
        {
            const char* str = "\0\0";
            return Token(0, 0, str, str + 1);
        }
    };
}
