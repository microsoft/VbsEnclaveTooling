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
    constexpr char RIGHT_CURLY_BRACKET = '}';
    constexpr char LEFT_CURLY_BRACKET = '{';
    constexpr char RIGHT_ROUND_BRACKET = ')';
    constexpr char LEFT_ROUND_BRACKET = '(';
    constexpr char RIGHT_SQUARE_BRACKET = ']';
    constexpr char LEFT_SQUARE_BRACKET = '[';
    constexpr char EQUAL_SIGN = '=';
    constexpr char SEMI_COLON = ';';
    constexpr char COMMA = ',';
    constexpr char FORWARD_SLASH = '/';
    constexpr char ASTERISK = '*';
    constexpr char DOUBLE_QUOTE = '"';
    constexpr char NEW_LINE_CHARACTER = '\n';
    constexpr char UNDERSCORE = '_';
    constexpr char CARRIAGE_RETURN = '\r';
    constexpr char BACKSPACE = '\b';
    constexpr char WHITE_SPACE = ' ';
    constexpr char VERTICAL_TAB = '\v';
    constexpr char HORIZONTAL_TAB = '\t';
    constexpr char END_OF_FILE_CHARACTER = '\0';
    constexpr const char* EDL_ENCLAVE_KEYWORD = "enclave";
    constexpr const char* EDL_TRUSTED_KEYWORD = "trusted";
    constexpr const char* EDL_UNTRUSTED_KEYWORD = "untrusted";
    constexpr const char* EDL_ENUM_KEYWORD = "enum";
    constexpr const char* EDL_STRUCT_KEYWORD = "struct";
    constexpr const std::uint32_t MINIMUM_HEX_LENGTH = 3;
    constexpr const std::uint32_t HEX_PREFIX_LENGTH = 2;
    constexpr const char* HEX_PREFIX[HEX_PREFIX_LENGTH] = { "0x", "0X"};

    static inline bool IsHexPrefix(const char* token_start)
    {
        for (auto& prefix : HEX_PREFIX)
        {
            if (token_start[0] == prefix[0] && (token_start[1] == prefix[1]))
            {
                return true;
            }
        }

        return false;
    }
}
