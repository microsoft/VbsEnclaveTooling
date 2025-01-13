// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
// 
// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
// This file has been modified and adapted from its original
// which was created by Open Enclave.

#pragma once
#include <pch.h>
#include "Structures.h"

namespace EdlProcessor
{
    // Responsible for analyzing an edl file and breaking its 
    // elements into individual tokens at runtime by walking
    // through an in memory string of the file content
    // character by character.
    class LexicalAnalyzer
    {
    public:
        LexicalAnalyzer(const std::filesystem::path& filepath);
        ~LexicalAnalyzer() = default;

        bool CanStartAnalysis() { return m_file_contents_loaded; }
        Token GetNextToken();
    private:
        void SkipWhiteSpaceAndComments();

        bool m_file_contents_loaded;
        std::filesystem::path m_file_name;
        std::string m_file {};
        const char* m_null_character_position{0};
        const char* m_cur_position_character {0};
        std::uint32_t m_line_number {0};
        std::uint32_t m_column_number {0};
    };
}
