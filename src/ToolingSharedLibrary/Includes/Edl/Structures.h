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

        bool operator==(std::string_view str) const
        {
            return str == std::string_view(m_starting_character, Length());
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

        std::uint32_t m_line_number{};
        std::uint32_t m_column_number{};
        const char* m_starting_character{};
        const char* m_ending_character{};
    };
}
