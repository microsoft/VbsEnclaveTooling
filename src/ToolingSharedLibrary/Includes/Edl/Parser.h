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
#include <Utils\Helpers.h>

using namespace ErrorHelpers;

namespace EdlProcessor
{
    enum class FunctionKind : uint32_t
    {
        Trusted,
        Untrusted,
    };


    enum class MapKind
    {
        DeveloperType,
        UntrustedFunction,
        TrustedFunction,
    };

    enum class ParseStatus
    {
        NotSeen,
        Parsing,
        Parsed,
    };

    struct ParsedState
    {
        ParseStatus m_status {ParseStatus::NotSeen};
        Edl m_edl{};
    };

    class EdlParser
    {
    public:
        EdlParser(
            const std::filesystem::path& file_path, 
            std::vector<std::filesystem::path> import_directories);

        ~EdlParser() = default;

        Edl Parse();

    private:
        void ParseInternal(std::unordered_map<std::filesystem::path, ParsedState>& parsed_files);
        void ParseEnum();
        void ParseStruct();
        void ParseFunctions(const FunctionKind& function_kind);
        void ValidatePointers(const Declaration& declaration);
        void PerformFinalValidations();
        void UpdateDeveloperTypeMetadata();

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
        void UpdateTypeDeclarations(std::span<Declaration> declarations);
        void MergeEdl(Edl& src_edl, Edl& dest_edl);

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
        Edl ParseBody(std::unordered_map<std::filesystem::path, ParsedState>& parsed_files);
        Edl GenerateEdlObject(std::unordered_map<std::filesystem::path, ParsedState>& parsed_files);
        void ParseImport(std::unordered_map<std::filesystem::path, ParsedState>& parsed_files);
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
        LexicalAnalyzer m_lexical_analyzer {};
        Token m_cur_token {};
        Token m_next_token {};
        std::uint32_t m_cur_line {};
        std::uint32_t m_cur_column {};
        std::unordered_set<std::string> m_unresolved_types{};
        OrderedMap<std::string, DeveloperType> m_developer_types {};
        OrderedMap<std::string, Function> m_trusted_functions;
        OrderedMap<std::string, Function> m_untrusted_functions;
        std::vector<std::filesystem::path> m_import_directories {};
        std::vector<std::filesystem::path> m_imported_edl_files {};
    };
}
