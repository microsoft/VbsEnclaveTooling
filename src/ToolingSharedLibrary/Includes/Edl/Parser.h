// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
// 
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// This file has been modified and adapted from its original
// which was created by Open Enclave.

#pragma once
#include <pch.h>
#include <ErrorHelpers.h>
#include <unordered_set>
#include "LexicalAnalyzer.h"
#include "Utils.h"

using namespace ErrorHelpers;

namespace EdlProcessor
{
    enum class FunctionKind : uint32_t
    {
        Trusted,
        Untrusted,
    };

    class EdlParser
    {
    public:
        EdlParser(const std::filesystem::path& file_path);
        ~EdlParser() = default;

        Edl Parse();
        
    private:
        void ParseEnum();
        void ParseStruct();
        void ParseFunctions(const FunctionKind& function_kind);
        void ValidatePointers(const Declaration& declaration);
        void PerformFinalValidations();

        void ParseThroughFieldsOrParameterList(
            const DeclarationParentKind& parent_kind, 
            std::string declaration_parent_name,
            std::vector<Declaration>& field_or_parameter_list,
            const char list_ending_character,
            const char list_item_separator_character);

        void AddDeveloperType(const DeveloperType& new_type);

        void ValidateSizeAndCountAttributeDeclarations(
            const std::string& parent_name,
            const std::vector<Declaration>& declarations);
            
        void ValidateNonSizeAndCountAttributes(const Declaration& declaration);

        inline void ThrowIfExpectedTokenNotNext(const char* token_expected_next);
        inline void ThrowIfExpectedTokenNotNext(char token_expected_next);
        inline void ThrowIfTokenNotIdentifier(const Token& token, const ErrorHelpers::ErrorId& error_id);
        inline void ThrowIfDuplicateDefinition(const std::string& type_name);
        inline void ThrowIfTypeNameIdentifierIsReserved(const std::string& name);
        inline void ThrowIfDuplicateFieldOrParamName(
            const std::unordered_set<std::string>& set,
            const std::string& struct_or_function_name,
            const Declaration& declaration);

        Token GetCurrentTokenAndMoveToNextToken();

        Token PeekAtCurrentToken();
        Token PeekAtNextToken();
        Edl ParseBody();
        Function ParseFunctionDeclaration();
        EdlTypeInfo ParseDeclarationTypeInfo();
        ArrayDimensions ParseArrayDimensions();
        EdlTypeInfo ParseVector();

        std::optional<ParsedAttributeInfo> ParseAttributes(
            const DeclarationParentKind& parent_kind,
            std::vector<std::pair<AttributeKind, Token>>& attribute_and_token_pairs);

        Declaration ParseDeclaration(const DeclarationParentKind& parent_kind);
        AttributeKind CheckAttributeIsValid(const Token& token);

        std::filesystem::path m_file_path;
        std::filesystem::path m_file_name;
        std::unique_ptr<LexicalAnalyzer> m_lexical_analyzer {};
        Token m_cur_token {};
        Token m_next_token {};
        std::uint32_t m_cur_line {};
        std::uint32_t m_cur_column {};

        std::vector<DeveloperType> m_developer_types_insertion_order_list {};
        std::unordered_map<std::string, DeveloperType> m_developer_types;
        std::unordered_map<std::string, Function> m_trusted_functions;
        std::unordered_map<std::string, Function> m_untrusted_functions;
    };
}
