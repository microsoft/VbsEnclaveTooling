// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
// 
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// This file has been modified and adapted from its original
// which was created by Open Enclave.

#pragma once
#include <pch.h>
#include <unordered_set>

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

        std::uint32_t m_line_number{};
        std::uint32_t m_column_number{};
        const char* m_starting_character{};
        const char* m_ending_character{};
    };

    enum class AttributeKind : std::uint32_t
    {
        In,
        Out,
        Count,
        Size,
    };

    enum class EdlTypeKind : std::uint32_t
    {
        Unknown,
        AnonymousEnum,
        Bool,
        Char,
        Float,
        Double,
        Int8,
        Int16,
        Int32,
        Int64,
        UInt8,
        UInt16,
        UInt32,
        UInt64,
        Void,
        WChar,
        Struct,
        Enum,
        Ptr,
        SizeT,
        String,
        WString,
        HRESULT,
        UIntPtr,
        Vector,
    };

    struct EdlTypeToHash
    {
        std::size_t operator()(EdlTypeKind type) const
        {
            return std::hash<std::uint32_t>()(static_cast<std::uint32_t>(type));
        }
    };

    inline const std::unordered_set<EdlTypeKind, EdlTypeToHash> c_edlTypes_primitive_set =
    {
        EdlTypeKind::Bool,
        EdlTypeKind::Char,
        EdlTypeKind::Float,
        EdlTypeKind::Double,
        EdlTypeKind::Int8,
        EdlTypeKind::Int16,
        EdlTypeKind::Int32,
        EdlTypeKind::Int64,
        EdlTypeKind::UInt8,
        EdlTypeKind::UInt16,
        EdlTypeKind::UInt32,
        EdlTypeKind::UInt64,
        EdlTypeKind::UIntPtr,
        EdlTypeKind::WChar,
        EdlTypeKind::Enum,
        EdlTypeKind::HRESULT,
        EdlTypeKind::SizeT,
    };

    struct ParsedAttributeInfo
    {
        bool IsSizeOrCountPresent() const
        {
            return !m_size_info.IsEmpty() || !m_count_info.IsEmpty();
        }

        bool IsInOutOrOutParameter() const
        {
            return m_in_and_out_present || m_out_present;
        }

        bool IsSizeMoreThanOne() const
        {
            if (m_size_info.IsIdentifier())
            {
                // developer using a variable for the size. In this case we'll
                // return true by default since it can change at runtime to any number.
                return true;
            }

            if (m_size_info.IsUnsignedInteger() && std::stoull(m_size_info.ToString()) > 1)
            {
                return true;
            }

            return false;
        }

        bool IsCountMoreThanOne() const
        {
            if (m_count_info.IsIdentifier())
            {
                // developer using a variable for the size. In this case we'll
                // return true by default since it can change at runtime to any number.
                return true;
            }

            if (m_count_info.IsUnsignedInteger() && std::stoull(m_count_info.ToString()) > 1)
            {
                return true;
            }

            return false;
        }

        bool IsCountOrSizeMoreThanOne() const
        {
            return IsCountMoreThanOne() || IsSizeMoreThanOne();
        }

        bool m_in_present{};
        bool m_out_present{};
        bool m_in_and_out_present{};

        Token m_size_info = Token::CreateEmptyToken();
        Token m_count_info = Token::CreateEmptyToken();
    };

    struct EdlTypeInfo
    {
        EdlTypeInfo() = default;

        EdlTypeInfo(const std::string& name)
            : m_name(name)
        {
        }

        EdlTypeInfo(const std::string& name, EdlTypeKind type)
            : m_name(name), m_type_kind(type)
        {
        }
        EdlTypeKind m_type_kind{};

        bool is_pointer{};
        std::string m_name{};
        std::shared_ptr<EdlTypeInfo> inner_type;
    };

    typedef std::vector<std::string> ArrayDimensions;

    enum class DeclarationParentKind : std::uint32_t
    {
        Struct,
        Function,
    };

    // A single declaration can be one of two things.
    // 1. A function parameter with its type and attribute information.
    // 2. Or A field within a struct with its type and attribute information.
    struct Declaration
    {
        Declaration(const DeclarationParentKind& parent_kind)
            : m_parent_kind(parent_kind)
        {
        }

        bool HasPointer() const
        {
            return m_edl_type_info.is_pointer;
        }

        bool IsInOutOrOutParameter() const
        {
            return IsInOutParameter() || IsOutParameter();
        }

        bool IsInOutParameter() const 
        {
            return m_attribute_info && m_attribute_info.value().m_in_and_out_present;
        }

        bool IsOutParameter() const
        {
            return m_attribute_info && m_attribute_info.value().m_out_present;
        }

        bool IsOutParameterOnly() const
        {
            return IsOutParameter() && !IsInOutParameter();
        }

        bool IsInParameter() const
        {
            return m_attribute_info && m_attribute_info.value().m_in_present;
        }

        bool IsInParameterOnly() const
        {
            return IsInParameter() && !IsOutParameter();
        }

        bool IsEdlType(EdlTypeKind type_kind) const
        {
            return m_edl_type_info.m_type_kind == type_kind;
        }

        bool IsInnerEdlType(EdlTypeKind type_kind) const
        {
            auto inner_type = m_edl_type_info.inner_type;
            if (!inner_type)
            {
                return false;
            }

            return inner_type->m_type_kind == type_kind;
        }

        bool HasPointerAndIsPointerToArray() const
        {
            if (m_attribute_info && m_attribute_info.value().IsCountOrSizeMoreThanOne())
            {
                return HasPointer();
            }

            return false;
        }

        bool IsSizeOrCountAttributeAnIdentifier() const
        {
            if (m_attribute_info)
            {
                return m_attribute_info.value().m_size_info.IsIdentifier() ||
                    m_attribute_info.value().m_count_info.IsIdentifier();
            }

            return false;
        }

        std::string GetSizeOrCountAttribute() const
        {
            std::string size_or_count {};
            if (TryGetSizeAttributeValue(size_or_count))
            {
                return size_or_count;
            }
            else
            {
                TryGetCountAttributeValue(size_or_count);
            }

            return size_or_count;
        }

        bool TryGetSizeAttributeValue(std::string& value) const
        {
            value = "";

            if (m_attribute_info && m_attribute_info.value().IsSizeMoreThanOne())
            {
                value = m_attribute_info.value().m_size_info.ToString();
                return true;
            }

            return false;
        }

        bool TryGetCountAttributeValue(std::string& value) const
        {
            if (m_attribute_info && m_attribute_info.value().IsCountMoreThanOne())
            {
                value = m_attribute_info.value().m_count_info.ToString();
                return true;
            }

            return false;
        }

        bool IsPrimitiveType() const
        {
            if (!m_array_dimensions.empty())
            {
                return false;
            }

            return c_edlTypes_primitive_set.contains(m_edl_type_info.m_type_kind);
        }

        std::string GenerateTypeInfoString()
        {
            std::string info_string = m_edl_type_info.m_name;

            // Add pointers
            if (m_edl_type_info.is_pointer)
            {
                info_string += "*";
            }

            // Add array dimensions
            for (auto& numeric_value : m_array_dimensions)
            {
                info_string += std::format("[{}]", numeric_value);
            }
            
            return info_string;
        }

        std::string m_name{};
        EdlTypeInfo m_edl_type_info{};
        ArrayDimensions m_array_dimensions{};
        DeclarationParentKind m_parent_kind{};
        std::optional<ParsedAttributeInfo> m_attribute_info{};
    };

    struct EnumType
    {
        EnumType(std::string name, std::uint64_t position)
            : m_name(name), m_declared_position(position)
        {
        }

        std::string m_name{};
        std::optional<Token> m_value{};

        // When the value isn't defined with an '=' symbol, the value of the enum
        // will be the position it appears in the edl file. e.g first will be 0,
        // second will be 1 etc. Note: This value always starts at zero but is
        // relative to the previous 'EnumType' value. e.g if the previous Enum value was set to
        // 100 using the '=' symbol, then any subsequent enum value will have its m_declared_position
        // set to 101.
        std::uint64_t m_declared_position{};

        bool m_is_hex{ false };

        // first value is always the default.
        bool m_is_default_value {};
    };

    // DeveloperTypes can be one of two things
    // 1. A Struct the developer created themselves
    // 2. Or An Enum
    struct DeveloperType
    {
        DeveloperType() = default;
        DeveloperType(std::string name, EdlTypeKind type)
            : m_name(name), m_type_kind(type)
        {
        }

        bool IsEdlType(EdlTypeKind type_kind) const
        {
            return m_type_kind == type_kind;
        }

        bool ContainsPointers() const
        {
            for (auto& field : m_fields)
            {
                if (field.HasPointer())
                {
                    return true;
                }
            }

            return false;
        }

        std::string m_name;
        EdlTypeKind m_type_kind;
        std::vector<Declaration> m_fields;
        std::unordered_map<std::string, EnumType> m_items;
    };

    struct Function
    {
        std::string GetDeclarationSignature()
        {
            if (!m_signature.empty())
            {
                return m_signature;
            }

            std::string parameter_string {};

            for (auto i = 0U; i < m_parameters.size() ; i++)
            {
                auto info_string = m_parameters[i].GenerateTypeInfoString();

                if (i + 1U < m_parameters.size())
                {
                    parameter_string += std::format("{},", info_string);
                }
                else
                {
                    parameter_string += std::format("{}", info_string);
                }
            }

            m_signature =  std::format("{}({})", m_name, parameter_string);

            return m_signature;
        }

        std::string m_name{};
        std::string abi_m_name {};
        Declaration m_return_info {DeclarationParentKind::Function};
        std::vector<Declaration> m_parameters{};
    private:
        std::string m_signature{};
    };

    struct Edl
    {
        std::string m_name{};
        std::unordered_map<std::string, DeveloperType> m_developer_types{};
        std::vector<DeveloperType> m_developer_types_insertion_order_list {};
        std::unordered_map<std::string, Function> m_trusted_functions{};
        std::unordered_map<std::string, Function> m_untrusted_functions{};
    };
}
