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
    constexpr char RIGHT_ARROW_BRACKET = '>';
    constexpr char LEFT_ARROW_BRACKET = '<';
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
    constexpr const char* EDL_IMPORT_KEYWORD = "import";
    constexpr const std::uint32_t MINIMUM_HEX_LENGTH = 3;
    constexpr const std::uint32_t HEX_PREFIX_LENGTH = 2;
    constexpr const char* HEX_PREFIX[HEX_PREFIX_LENGTH] = { "0x", "0X"};

    // Special keyword for internal use for the anonymous enum value.
    constexpr const char* EDL_ANONYMOUS_ENUM_KEYWORD = "__anonymous_enum";

    static const std::unordered_map<EdlTypeKind, std::string, EdlTypeToHash> c_edlTypes_to_string_map =
    {
        { EdlTypeKind::Bool, "bool" },
        { EdlTypeKind::Char, "char" },
        { EdlTypeKind::Float, "float" },
        { EdlTypeKind::Double, "double" },
        { EdlTypeKind::Int8, "int8_t" },
        { EdlTypeKind::Int16, "int16_t" },
        { EdlTypeKind::Int32, "int32_t" },
        { EdlTypeKind::Int64, "int64_t" },
        { EdlTypeKind::UInt8, "uint8_t" },
        { EdlTypeKind::UInt16, "uint16_t" },
        { EdlTypeKind::UInt32, "uint32_t" },
        { EdlTypeKind::UInt64, "uint64_t" },
        { EdlTypeKind::WChar, "wchar_t" },
        { EdlTypeKind::Void, "void" },
        { EdlTypeKind::Enum, "enum" },
        { EdlTypeKind::HRESULT, "HRESULT" },
        { EdlTypeKind::AnonymousEnum, EDL_ANONYMOUS_ENUM_KEYWORD},
        { EdlTypeKind::Struct, "struct" },
        { EdlTypeKind::Ptr, "*" },
        { EdlTypeKind::SizeT, "size_t" },
        { EdlTypeKind::String, "string" },
        { EdlTypeKind::WString, "wstring" },
        { EdlTypeKind::UIntPtr, "uintptr_t" },
        { EdlTypeKind::Vector, "vector" },
    };

    static const std::unordered_map<std::string, EdlTypeKind> c_string_to_edltype_map =
    {
        { "bool", EdlTypeKind::Bool },
        { "char", EdlTypeKind::Char },
        { "float", EdlTypeKind::Float },
        { "double", EdlTypeKind::Double },
        { "int8_t", EdlTypeKind::Int8 },
        { "int16_t", EdlTypeKind::Int16 },
        { "int32_t", EdlTypeKind::Int32 },
        { "int64_t", EdlTypeKind::Int64 },
        { "uint8_t", EdlTypeKind::UInt8 },
        { "uint16_t", EdlTypeKind::UInt16 },
        { "uint32_t", EdlTypeKind::UInt32 },
        { "uint64_t", EdlTypeKind::UInt64 },
        { "wchar_t", EdlTypeKind::WChar },
        { "void", EdlTypeKind::Void },
        { "HRESULT", EdlTypeKind::HRESULT },
        { "enum", EdlTypeKind::Enum },
        { EDL_ANONYMOUS_ENUM_KEYWORD, EdlTypeKind::AnonymousEnum },
        { "struct", EdlTypeKind::Struct },
        { "string", EdlTypeKind::String },
        { "wstring", EdlTypeKind::WString },
        { "*", EdlTypeKind::Ptr },
        { "size_t", EdlTypeKind::SizeT },
        { "uintptr_t", EdlTypeKind::UIntPtr },
        { "vector", EdlTypeKind::Vector },
    };

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

    static inline bool TokenMeetsMinimumHexLength(const Token& token)
    {
        return token.Length() >= MINIMUM_HEX_LENGTH;
    }

    static inline bool TryParseHexidecimal(const Token& token, uint64_t& value)
    {
        if (!TokenMeetsMinimumHexLength(token) || !IsHexPrefix(token.m_starting_character))
        {
            return false;
        }

        for (auto i = HEX_PREFIX_LENGTH; i < token.Length(); i++)
        {
            if (!std::isxdigit(token.m_starting_character[i]))
            {
                return false;
            }
        }

        std::stringstream string_stream;
        string_stream << std::hex << (token.m_starting_character + HEX_PREFIX_LENGTH);
        string_stream >> value;

        return true;
    }

    static inline bool TryParseDecimal(const Token& token, uint64_t& value)
    {
        if (token.Length() == 0)
        {
            return false;
        }

        for (auto i = 0; i < token.Length(); i++)
        {
            if (!std::isdigit(token.m_starting_character[i]))
            {
                return false;
            }
        }

        std::stringstream() << token.m_starting_character >> value;

        return true;
    }

    static inline constexpr std::string_view c_default_count_value = "1";

    inline std::string GetSizeFromAttribute(const Declaration& declaration)
    {
        std::string copy_length = declaration.GetSizeOrCountAttribute();

        if (!copy_length.empty())
        {
            return copy_length;
        }
        else
        {
            return c_default_count_value.data();
        }
    }
}
