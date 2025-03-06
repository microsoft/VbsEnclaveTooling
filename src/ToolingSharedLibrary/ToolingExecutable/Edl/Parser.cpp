// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
// 
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// This file has been modified and adapted from its original
// which was created by Open Enclave.

#include <pch.h>
#include <Edl\Parser.h>
#include <Exceptions.h>

using namespace ToolingExceptions;

namespace EdlProcessor
{
    static const std::uint32_t c_max_number_of_pointers = 1;

    EdlParser::EdlParser(const std::filesystem::path& file_path)
        : m_file_path(file_path), m_file_name(m_file_path.filename().replace_extension()), m_cur_line(1), m_cur_column(1)
    {
    }

    Token EdlParser::PeekAtCurrentToken()
    {
        return m_cur_token;
    }

    Token EdlParser::PeekAtNextToken()
    {
        return m_next_token;
    }

    Token EdlParser::GetCurrentTokenAndMoveToNextToken()
    {
        Token token = m_cur_token;
        m_cur_token = m_next_token;
        m_next_token = m_lexical_analyzer->GetNextToken();
        m_cur_line = token.m_line_number;
        m_cur_column = token.m_column_number;
        return token;
    }

    inline void EdlParser::ThrowIfExpectedTokenNotNext(const char* expected_token)
    {
        Token actual_next_token = GetCurrentTokenAndMoveToNextToken();

        if (actual_next_token != expected_token)
        {
            throw EdlAnalysisException(
                ErrorId::EdlExpectedTokenNotFound,
                m_file_name,
                actual_next_token.m_line_number,
                actual_next_token.m_column_number,
                expected_token,
                actual_next_token.ToString());
        }
    }

    inline void EdlParser::ThrowIfExpectedTokenNotNext(char expected_char)
    {
        char expected_string[] = {expected_char, END_OF_FILE_CHARACTER};
        ThrowIfExpectedTokenNotNext(expected_string);
    }

    inline void EdlParser::ThrowIfTokenNotIdentifier(const Token& token, const ErrorId& error_id)
    {
        if (!token.IsIdentifier())
        {
            throw EdlAnalysisException(
                error_id,
                m_file_name,
                m_cur_line,
                m_cur_column,
                token.ToString());
        }
    }

    inline void EdlParser::ThrowIfDuplicateDefinition(const std::string& type_name)
    {
        if (m_developer_types.contains(type_name))
        {
            throw EdlAnalysisException(
                ErrorId::EdlDuplicateTypeDefinition,
                m_file_name,
                m_cur_line,
                m_cur_column,
                type_name);
        }
    }

    inline void EdlParser::ThrowIfTypeNameIdentifierIsReserved(const std::string& name)
    {
        if (c_string_to_edltype_map.contains(name))
        {
            throw EdlAnalysisException(
                ErrorId::EdlTypeNameIdentifierIsReserved,
                m_file_name,
                m_cur_line,
                m_cur_column,
                name);
        }
    }

    inline void EdlParser::ThrowIfDuplicateFieldOrParamName(
        const std::unordered_set<std::string>& set,
        const std::string& struct_or_function_name,
        const Declaration& declaration)
    {
        if (set.contains(declaration.m_name))
        {
            throw EdlAnalysisException(
                ErrorId::EdlDuplicateFieldOrParameter,
                m_file_name,
                m_cur_line,
                m_cur_column,
                declaration.m_name,
                struct_or_function_name);
        }
    }

    Edl EdlParser::Parse()
    {
        std::string status = std::format("Processing {}", m_file_name.generic_string());
        PrintStatus(Status::Info, status);

        // Start LexicalAnalyzer so we can walk through .edl file.
        m_lexical_analyzer = std::make_unique<LexicalAnalyzer>(m_file_path);
        m_cur_token = m_lexical_analyzer->GetNextToken();
        m_next_token = m_lexical_analyzer->GetNextToken();

        ThrowIfExpectedTokenNotNext(EDL_ENCLAVE_KEYWORD);
        ThrowIfExpectedTokenNotNext(LEFT_CURLY_BRACKET);
        Edl edl = ParseBody();
        edl.m_name = m_file_name.generic_string();
        ThrowIfExpectedTokenNotNext(RIGHT_CURLY_BRACKET);

        status = std::format("Completed parsing {} successfully", m_file_name.generic_string());
        PrintStatus(Status::Info, status);

        return std::move(edl);
    }

    Edl EdlParser::ParseBody()
    {
        while (PeekAtCurrentToken() != RIGHT_CURLY_BRACKET && PeekAtCurrentToken() != END_OF_FILE_CHARACTER)
        {
            Token token = GetCurrentTokenAndMoveToNextToken();

            if (token == EDL_TRUSTED_KEYWORD)
            {
                ParseFunctions(FunctionKind::Trusted);
            }
            else if (token == EDL_UNTRUSTED_KEYWORD)
            {
                ParseFunctions(FunctionKind::Untrusted);
            }
            else if (token == EDL_ENUM_KEYWORD)
            {
                ParseEnum();
            }
            else if (token == EDL_STRUCT_KEYWORD)
            {
                ParseStruct();
            }
            else
            {
                throw EdlAnalysisException(
                    ErrorId::EdlUnexpectedToken,
                    m_file_name,
                    token.m_line_number,
                    token.m_column_number,
                    token.ToString());
            }
        }

        PerformFinalValidations();

        return Edl{
            m_file_name.generic_string(),
            m_developer_types,
            m_trusted_functions,
            m_untrusted_functions };
    }

    void EdlParser::AddDeveloperType(const std::shared_ptr<DeveloperType>& new_type)
    {

        if (m_unresolved_type_names.contains(new_type->m_name))
        {
            // update all unresolved types from EdlTypeKind::Unknown to their correct
            // types if the type was defined after we first saw it.
            for (auto& type_info : m_unresolved_type_names.at(new_type->m_name))
            {
                type_info.m_type_kind = new_type->m_type_kind;;
            }

            m_unresolved_type_names.erase(new_type->m_name);
        }

        m_developer_types.emplace(new_type->m_name, new_type);
    }

    void EdlParser::ParseEnum()
    {
        Token enum_identifier_token = GetCurrentTokenAndMoveToNextToken();
        std::shared_ptr<DeveloperType> new_enum_type{};
        bool is_anonymous_enum = enum_identifier_token == LEFT_CURLY_BRACKET;

        if (is_anonymous_enum)
        {
            // Handle anonymous enum type
            if (!m_developer_types.contains(EDL_ANONYMOUS_ENUM_KEYWORD))
            {
                m_developer_types[EDL_ANONYMOUS_ENUM_KEYWORD] = 
                    std::make_shared<DeveloperType>(EDL_ANONYMOUS_ENUM_KEYWORD, EdlTypeKind::AnonymousEnum);
            }
            
            new_enum_type = m_developer_types[EDL_ANONYMOUS_ENUM_KEYWORD];
        }
        else
        {
            // Handle enum with name identifier.
            ThrowIfTokenNotIdentifier(enum_identifier_token, ErrorId::EdlEnumNameIdentifierNotFound);
            new_enum_type = std::make_shared <DeveloperType>(enum_identifier_token.ToString(), EdlTypeKind::Enum);
            ThrowIfTypeNameIdentifierIsReserved(new_enum_type->m_name);
            ThrowIfDuplicateDefinition(new_enum_type->m_name);

            // Move past starting '{' token.
            GetCurrentTokenAndMoveToNextToken();
        }

        std::uint64_t cur_enum_value_position = 0;
        bool was_previous_value_hex = false;

        while (PeekAtCurrentToken() != RIGHT_CURLY_BRACKET)
        {
            Token enum_value_identifier = GetCurrentTokenAndMoveToNextToken();
            auto value_name = enum_value_identifier.ToString();

            if (!is_anonymous_enum && !enum_value_identifier.IsIdentifier())
            {
                throw EdlAnalysisException(
                    ErrorId::EdlEnumValueIdentifierNotFound,
                    m_file_name,
                    m_cur_line,
                    m_cur_column,
                    value_name);
            }

            std::optional<Token> actual_enum_value = {};
            auto enum_type = EnumType(value_name, cur_enum_value_position);
            enum_type.m_is_hex = was_previous_value_hex;

            // Enum value definitions don't need to have the '=' sign and an associated
            // integer value. For these cases we'll simply move on to the next one and
            // will use the 'cur_enum_value_position' value as its fallback value.
            if (PeekAtCurrentToken() == EQUAL_SIGN)
            {
                // Current token is '=' so move cursor to next character which should be
                // the enum values identifier.
                GetCurrentTokenAndMoveToNextToken();
                Token enum_value_token = GetCurrentTokenAndMoveToNextToken();

                std::uint64_t hex_value{};
                bool is_hex = TryParseHexidecimal(enum_value_token, hex_value);

                std::uint64_t decimal_value{};
                bool is_decimal = TryParseDecimal(enum_value_token, decimal_value);

                if (is_decimal)
                {
                    enum_type.m_declared_position = decimal_value;
                    cur_enum_value_position = decimal_value;
                    was_previous_value_hex = false;
                    enum_type.m_is_hex = false;
                }
                else if (is_hex)
                {
                    enum_type.m_declared_position = hex_value;
                    cur_enum_value_position = hex_value;
                    enum_type.m_is_hex = true;
                    was_previous_value_hex = true;
                }
                else
                {
                    throw EdlAnalysisException(
                        ErrorId::EdlEnumValueNotFound,
                        m_file_name,
                        m_cur_line,
                        m_cur_column,
                        enum_value_token.ToString());
                }

                enum_type.m_value = enum_value_token;
            }

            if (PeekAtCurrentToken() != RIGHT_CURLY_BRACKET)
            {
                // Since we're not at the end of the enum definition, we should expect more values.
                // so confirm that a comma is the next token.
                ThrowIfExpectedTokenNotNext(COMMA);
            }

            if (new_enum_type->m_items.contains(value_name))
            {
                throw EdlAnalysisException(
                    ErrorId::EdlEnumNameDuplicated,
                    m_file_name,
                    m_cur_line,
                    m_cur_column,
                    value_name);
            }

            new_enum_type->m_items.emplace(value_name, enum_type);
            cur_enum_value_position++;
        }

        ThrowIfExpectedTokenNotNext(RIGHT_CURLY_BRACKET);
        ThrowIfExpectedTokenNotNext(SEMI_COLON);

        AddDeveloperType(new_enum_type);
    }

    void EdlParser::ParseThroughFieldsOrParameterList(
        const DeclarationParentKind& parent_kind,
        std::string declaration_parent_name,
        std::vector<Declaration>& field_or_parameter_list,
        const char list_ending_character,
        const char list_item_separator_character)
    {
        std::unordered_set<std::string> param_names {};

        while (PeekAtCurrentToken() != list_ending_character)
        {
            Declaration declaration = ParseDeclaration(parent_kind);
            ValidatePointers(declaration);
            ThrowIfDuplicateFieldOrParamName(param_names, declaration_parent_name, declaration);
            field_or_parameter_list.push_back(declaration);

            param_names.emplace(declaration.m_name);

            if (PeekAtCurrentToken() != list_ending_character)
            {
                // At this point if we're not at the end of the declaration we should expect there
                // to be more comma separated parameters if we're looking at a function. Or a semi
                // colon which separates each field if we're looking at a struct.
                ThrowIfExpectedTokenNotNext(list_item_separator_character);
            }
        }
    }

    void EdlParser::ParseStruct()
    {
        Token struct_name_identifier = GetCurrentTokenAndMoveToNextToken();
        ThrowIfTokenNotIdentifier(struct_name_identifier, ErrorId::EdlStructIdentifierNotFound);
        auto new_struct_type = std::make_shared<DeveloperType>(struct_name_identifier.ToString(), EdlTypeKind::Struct);
        
        ThrowIfTypeNameIdentifierIsReserved(new_struct_type->m_name);
        ThrowIfDuplicateDefinition(new_struct_type->m_name);
        ThrowIfExpectedTokenNotNext(LEFT_CURLY_BRACKET);
        std::unordered_set<std::string> param_names{};

        ParseThroughFieldsOrParameterList(
            DeclarationParentKind::Struct,
            new_struct_type->m_name,
            new_struct_type->m_fields,
            RIGHT_CURLY_BRACKET,
            SEMI_COLON);

        ThrowIfExpectedTokenNotNext(RIGHT_CURLY_BRACKET);
        ThrowIfExpectedTokenNotNext(SEMI_COLON);   
        
        AddDeveloperType(new_struct_type);
    }

    void EdlParser::ParseFunctions(const FunctionKind& function_kind)
    {
        ThrowIfExpectedTokenNotNext(LEFT_CURLY_BRACKET);
        auto& map = (function_kind == FunctionKind::Trusted)
            ? m_trusted_functions
            : m_untrusted_functions;

        while (PeekAtCurrentToken() != RIGHT_CURLY_BRACKET)
        {
            Function parsed_function = ParseFunctionDeclaration();
            std::string function_signature = parsed_function.GetDeclarationSignature();

            if (map.contains(function_signature))
            {
                throw EdlAnalysisException(
                    ErrorId::EdlDuplicateFunctionDeclaration,
                    m_file_name,
                    m_cur_line,
                    m_cur_column,
                    parsed_function.m_name);
            }

            map.emplace(function_signature, parsed_function);
        }

        ThrowIfExpectedTokenNotNext(RIGHT_CURLY_BRACKET);
        ThrowIfExpectedTokenNotNext(SEMI_COLON);
    }

    Function EdlParser::ParseFunctionDeclaration()
    {
        Function function{};
        function.m_return_info = ParseDeclarationTypeInfo();
        Token function_name_token = GetCurrentTokenAndMoveToNextToken();
        ThrowIfTokenNotIdentifier(function_name_token, ErrorId::EdlFunctionIdentifierNotFound);
        function.m_name = function_name_token.ToString();

        // Return of pointers aren't allowed. Only primitive types and structs as values. Pointers
        // in structs must have a an associated size/count attribute, so by preventing the return of pointers directly
        // developers must enclose them in structs. This way the abi layer can properly copy the underlying memory to 
        // the appropriate virtual trust layer as it will know the size of the data the pointer points to.
        auto return_kind = function.m_return_info.m_type_kind;
        if (function.m_return_info.is_pointer)
        {
            throw EdlAnalysisException(
                ErrorId::EdlReturnValuesCannotBePointers,
                m_file_name,
                m_cur_line,
                m_cur_column,
                function.m_name);
        }

        ThrowIfTypeNameIdentifierIsReserved(function.m_name);
        ThrowIfExpectedTokenNotNext(LEFT_ROUND_BRACKET);

        ParseThroughFieldsOrParameterList(
            DeclarationParentKind::Function,
            function.m_name,
            function.m_parameters,
            RIGHT_ROUND_BRACKET,
            COMMA);

        ThrowIfExpectedTokenNotNext(RIGHT_ROUND_BRACKET);
        ThrowIfExpectedTokenNotNext(SEMI_COLON);

        return function;
    }

    Declaration EdlParser::ParseDeclaration(const DeclarationParentKind& parent_kind)
    {
        std::vector<std::pair<AttributeKind, Token>> attribute_and_token_pairs{};
        auto declaration = Declaration(parent_kind);
        declaration.m_attribute_info = ParseAttributes(parent_kind, attribute_and_token_pairs);
        declaration.m_edl_type_info = ParseDeclarationTypeInfo();
        Token declaration_name_token = GetCurrentTokenAndMoveToNextToken();
        ThrowIfTokenNotIdentifier(declaration_name_token, ErrorId::EdlIdentifierNameNotFound);
        declaration.m_name = declaration_name_token.ToString();

        ThrowIfTypeNameIdentifierIsReserved(declaration.m_name);

        // The declaration may be an array so we need to get all of its dimensions.
        declaration.m_array_dimensions = ParseArrayDimensions();
        ValidateNonSizeAndCountAttributes(declaration);
        return declaration;
    }

    AttributeKind EdlParser::CheckAttributeIsValid(const Token& token)
    {
        if (token == "in")
        {
            return AttributeKind::In;
        }

        if (token == "out")
        {
            return AttributeKind::Out;
        }

        if (token == "count")
        {
            return AttributeKind::Count;
        }

        if (token == "size")
        {
            return AttributeKind::Size;
        }

        throw EdlAnalysisException(
            ErrorId::EdlInvalidAttribute,
            m_file_name,
            m_cur_line,
            m_cur_column,
            token.ToString());
    }

    std::optional<ParsedAttributeInfo> EdlParser::ParseAttributes(
        const DeclarationParentKind& parent_kind,
        std::vector<std::pair<AttributeKind, Token>>& attribute_and_token_pairs)
    {
        // Edl attribute will only ever be within square brackets next to an identifier
        // e.g [in] uint_8 byte
        if (PeekAtCurrentToken() != LEFT_SQUARE_BRACKET)
        {
            return {};
        }

        GetCurrentTokenAndMoveToNextToken();
        auto attributeInfo = ParsedAttributeInfo();
        while (PeekAtCurrentToken() != RIGHT_SQUARE_BRACKET)
        {
            Token token = GetCurrentTokenAndMoveToNextToken();
            AttributeKind attribute = CheckAttributeIsValid(token);

            // Only count and size attributes are valid for struct properties.
            bool isParsingStruct = parent_kind == DeclarationParentKind::Struct;
            bool isAttributesizeOrCount =
                (attribute == AttributeKind::Count) || (attribute == AttributeKind::Size);

            if (isParsingStruct && !isAttributesizeOrCount)
            {
                throw EdlAnalysisException(
                    ErrorId::EdlNonSizeOrCountAttributeInStruct,
                    m_file_name,
                    m_cur_line,
                    m_cur_column);
            }

            // Check for duplicate attributes within the square brackets e.g [size=12,size=13].
            for (auto&& attribute_and_token_pair : attribute_and_token_pairs)
            {
                if (attribute_and_token_pair.first == attribute)
                {
                    throw EdlAnalysisException(
                        ErrorId::EdlDuplicateAttributeFound,
                        m_file_name,
                        m_cur_line,
                        m_cur_column);
                }
            }

            attribute_and_token_pairs.push_back(std::make_pair(attribute, token));

            // Process the attribute.
            if (isAttributesizeOrCount)
            {
                ThrowIfExpectedTokenNotNext(EQUAL_SIGN);
                Token attribute_value = GetCurrentTokenAndMoveToNextToken();

                if (!attribute_value.IsIdentifier() && !attribute_value.IsUnsignedInteger())
                {
                    throw EdlAnalysisException(
                        ErrorId::EdlSizeOrCountValueInvalid,
                        m_file_name,
                        m_cur_line,
                        m_cur_column,
                        attribute_value.ToString());
                }

                if (attribute == AttributeKind::Size)
                {
                    attributeInfo.m_size_info = attribute_value;
                }
                else if (attribute == AttributeKind::Count)
                {
                    attributeInfo.m_count_info = attribute_value;
                }
            }
            else if (attribute == AttributeKind::In)
            {
                attributeInfo.m_in_present = true;
            }
            else if (attribute == AttributeKind::Out)
            {
                attributeInfo.m_out_present = true;
            }

            attributeInfo.m_in_and_out_present = attributeInfo.m_in_present && attributeInfo.m_out_present;

            // Check that we aren't at the end of the attributes.
            // If not expect a comma and move the position to the token.
            if (PeekAtCurrentToken() != RIGHT_SQUARE_BRACKET)
            {
                ThrowIfExpectedTokenNotNext(COMMA);
            }
        };

        ThrowIfExpectedTokenNotNext(RIGHT_SQUARE_BRACKET);

        return attributeInfo;
    }

    EdlTypeInfo EdlParser::ParseDeclarationTypeInfo()
    {
        Token type_token = GetCurrentTokenAndMoveToNextToken();
        ThrowIfTokenNotIdentifier(type_token, ErrorId::EdlIdentifierNameNotFound);
        auto type_name = type_token.ToString();
        auto type_info = EdlTypeInfo(type_name);

        // Check if keyword type is a type we support out of the box by default.
        if (c_string_to_edltype_map.contains(type_name))
        {
            type_info.m_type_kind = c_string_to_edltype_map.at(type_name);
        }
        else if (m_developer_types.contains(type_name))
        {
            auto& developer_type = m_developer_types.at(type_name);
            type_info.m_type_kind = developer_type->m_type_kind;
        }
        else
        {
            // Custom type that isn't defined yet.
            type_info.m_type_kind = EdlTypeKind::Unknown;
            m_unresolved_type_names[type_name].push_back(type_info);
        }

        // Add the pointer if it exists.
        if (PeekAtCurrentToken() == ASTERISK)
        {
            Token pointer_token = GetCurrentTokenAndMoveToNextToken();
            type_info.is_pointer = true;

            // Pointers to pointers not supported.
            if (PeekAtCurrentToken() == ASTERISK)
            {
                throw EdlAnalysisException(
                    ErrorId::EdlPointerToPointerInvalid,
                    m_file_name,
                    m_cur_line,
                    m_cur_column);
            }
        }

        return type_info;
    }

    ArrayDimensions EdlParser::ParseArrayDimensions()
    {
        ArrayDimensions dimensions{};

        // Return early if the current token isn't the start of an array dimension.
        if (PeekAtCurrentToken() != LEFT_SQUARE_BRACKET)
        {
            return dimensions;
        }

        while (PeekAtCurrentToken() == LEFT_SQUARE_BRACKET)
        {
            // Move past '[' to get value within it.
            GetCurrentTokenAndMoveToNextToken();
            Token array_value_token = GetCurrentTokenAndMoveToNextToken();
            auto token_name = array_value_token.ToString();
            bool is_integer = array_value_token.IsUnsignedInteger();
            bool is_valid_identifier = false;

            if (array_value_token.IsIdentifier() &&
                m_developer_types.contains(EDL_ANONYMOUS_ENUM_KEYWORD))
            {
                // token identifier can only be a value from an
                // anonymous enum.
                auto& type = m_developer_types.at(EDL_ANONYMOUS_ENUM_KEYWORD);
                is_valid_identifier = type->m_items.contains(token_name);
            }


            // The value inside the square brackets can be an
            // integer or a variable defined within the struct/function file.
            if (!is_integer && !is_valid_identifier)
            {
                throw EdlAnalysisException(
                    ErrorId::EdlArrayDimensionIdentifierInvalid,
                    m_file_name,
                    m_cur_line,
                    m_cur_column,
                    array_value_token.ToString());
            }

            dimensions.push_back(array_value_token.ToString());
            ThrowIfExpectedTokenNotNext(RIGHT_SQUARE_BRACKET);
        }

        return dimensions;
    }

    void EdlParser::ValidatePointers(const Declaration& declaration)
    {
        // Only proceed if the extended type is a pointer.
        if (!declaration.HasPointer())
        {
            return;
        }

        auto message = GetErrorMessageById(
               ErrorId::EdlPointerSizeAttributeMissing,
               declaration.m_name,
               m_cur_line,
               m_cur_column,
               declaration.m_edl_type_info.m_name);
        
        bool is_void_ptr = declaration.m_edl_type_info.m_type_kind == EdlTypeKind::Void;
        
        if (!declaration.m_attribute_info)
        {
            // Disallow void*'s that do not contain a size attribute. For all other pointer
            // types that don't contain an attribute, the code gen layer will copy sizeof(type)
            // when copying the pointer between virtual trust layers.
            if (is_void_ptr)
            {
                throw EdlAnalysisException(
                    ErrorId::EdlPointerToVoidMustBeAnnotated,
                    m_file_name,
                    m_cur_line,
                    m_cur_column);
            }

            PrintStatus(Status::Warning, message);
            return;
        }

        // Make sure pointer declarations are annotated with a size
        auto attribute_info = declaration.m_attribute_info.value();

        if (is_void_ptr && attribute_info.m_size_info.IsEmpty())
        {
            throw EdlAnalysisException(
               ErrorId::EdlPointerToVoidMustBeAnnotated,
               m_file_name,
               m_cur_line,
               m_cur_column);
        }

        if (!attribute_info.IsSizeOrCountPresent())
        {
            PrintStatus(Status::Warning, message);
        }

        bool in_or_out_present = (attribute_info.m_in_present) || (attribute_info.m_out_present);

        if (declaration.m_parent_kind == DeclarationParentKind::Function)
        {
            // Ponters in functions must have an associated in or out attribute.
            if (!in_or_out_present)
            {
                throw EdlAnalysisException(
                    ErrorId::EdlPointerMustBeAnnotatedWithDirection,
                    m_file_name,
                    m_cur_line,
                    m_cur_column);

            }

            // Pointers to arrays are not valid in the edl file.
            if (in_or_out_present && !declaration.m_array_dimensions.empty())
            {
                throw EdlAnalysisException(
                    ErrorId::EdlPointerToArrayNotAllowed,
                    m_file_name,
                    m_cur_line,
                    m_cur_column);

            }
        }
    }

    void EdlParser::ValidateNonSizeAndCountAttributes(const Declaration& declaration)
    {
        // Only continue if there are attributes to validate
        if (!declaration.m_attribute_info)
        {
            return;
        }

        auto info = declaration.m_attribute_info.value();

        if (info.IsSizeOrCountPresent() && !declaration.HasPointer())
        {
            throw EdlAnalysisException(
                ErrorId::EdlSizeAndCountNotValidForNonPointer,
                m_file_name,
                m_cur_line,
                m_cur_column,
                declaration.m_edl_type_info.m_name);
        }
    }

    static std::vector<Token> GetSizeOrCountAttributeTokens(const Declaration& declaration)
    {
        std::vector<Token> tokens;

        if (declaration.m_attribute_info)
        {
            ParsedAttributeInfo info = declaration.m_attribute_info.value();
            if (!info.m_size_info.IsEmpty())
            {
                tokens.push_back(info.m_size_info);
            }

            if (!info.m_count_info.IsEmpty())
            {
                tokens.push_back(info.m_size_info);
            }
        }

        return tokens;
    }

    static std::optional<Declaration> FindDeclaration(
        const std::vector<Declaration>& declarations,
        const std::string& name)
    {
        for (auto& declaration : declarations)
        {
            if (declaration.m_name == name)
            {
                return declaration;
            }
        }

        return {};
    }

    void EdlParser::PerformFinalValidations()
    {
        // Confirm there are no developer types that are without definitions
        for (const auto& [type_name, unresolved_list] : m_unresolved_type_names)
        {
            if (!unresolved_list.empty())
            {
                throw EdlAnalysisException(
                    ErrorId::EdlTypenameInvalid,
                    m_file_name,
                    m_cur_line,
                    m_cur_column,
                    type_name);
            }
        }

        // now that we've finished parsing the function declarations and structs 
        // Make sure the size/count attributes are validated.
        for (const auto& [function_name, function] : m_trusted_functions)
        {
            ValidateSizeAndCountAttributeDeclarations(function_name, function.m_parameters);
        }

        for (const auto& [function_name, function] : m_untrusted_functions)
        {
            ValidateSizeAndCountAttributeDeclarations(function_name, function.m_parameters);
        }

        for (const auto& [name, developer_type] : m_developer_types)
        {
            ValidateSizeAndCountAttributeDeclarations(name, developer_type->m_fields);
        }

    }

    void EdlParser::ValidateSizeAndCountAttributeDeclarations(
        const std::string& parent_name,
        const std::vector<Declaration>& declarations)
    {
        for (auto& declaration : declarations)
        {
            std::vector<Token> tokens = GetSizeOrCountAttributeTokens(declaration);
            for (Token& token : tokens)
            {
                // Value is an integer literal if its not an identifier.
                if (!token.IsIdentifier())
                {
                    continue;
                }

                bool identifier_in_anonymous_enum = false;

                // Identifier types for the size/count attributes should be enum
                // values from the anonymous enum type, or an unsigned integer literal
                // or an unsigned value field within a struct or an unsigned value
                // within a function parameter.
                if (m_developer_types.contains(EDL_ANONYMOUS_ENUM_KEYWORD))
                {
                    auto type = m_developer_types.at(EDL_ANONYMOUS_ENUM_KEYWORD);
                    if (type->m_items.contains(token.ToString()))
                    {
                        continue;
                    }
                }

                // Get the declaration that the size or count attribute refers to.
                auto declaration_found = FindDeclaration(declarations, token.ToString());

                if (!declaration_found)
                {
                    throw EdlAnalysisException(
                        ErrorId::EdlSizeOrCountAttributeNotFound,
                        m_file_name,
                        m_cur_line,
                        m_cur_column,
                        token.ToString(),
                        parent_name);
                }

                // The declaration should not point to an array. Only the value types listed above.
                if (!declaration_found.value().m_array_dimensions.empty())
                {
                    throw EdlAnalysisException(
                        ErrorId::EdlSizeOrCountForArrayNotValid,
                        m_file_name,
                        m_cur_line,
                        m_cur_column,
                        parent_name);
                }

                EdlTypeKind type = declaration_found.value().m_edl_type_info.m_type_kind;

                switch (type)
                {
                    case EdlTypeKind::UInt8:
                    case EdlTypeKind::UInt16:
                    case EdlTypeKind::UInt32:
                    case EdlTypeKind::UInt64:
                    case EdlTypeKind::SizeT:
                        continue;
                    default:
                        throw EdlAnalysisException(
                            ErrorId::EdlSizeOrCountInvalidType,
                            m_file_name,
                            m_cur_line,
                            m_cur_column,
                            c_edlTypes_to_string_map.at(type),
                            parent_name);
                }
            }
        }
    }
}
