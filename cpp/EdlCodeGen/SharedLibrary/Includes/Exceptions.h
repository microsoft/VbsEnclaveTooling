// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once 
#include <pch.h>
#include <exception>
#include "ErrorHelpers.h"

using namespace ErrorHelpers;

namespace ToolingExceptions
{
    class EdlAnalysisException: public std::exception
    {
    public:
        template<typename... Args>
        EdlAnalysisException(
            ErrorId id,
            const std::filesystem::path& file_name,
            std::uint32_t line_num,
            std::uint32_t column_num,
            Args&&... args)
        {
            m_message = std::format("{}: line: {}, column: {}\n", file_name.generic_string(), line_num, column_num);
            m_message += GetErrorMessageById(id, std::forward<Args>(args)...);
            m_id = id;
        }

        template<typename... Args>
        EdlAnalysisException(
            ErrorId id,
            const std::filesystem::path& file_name)
        {
            m_message = GetErrorMessageById(id, file_name.generic_string());
            m_id = id;
        }

        const char* what() const noexcept override
        {
            return m_message.c_str();
        }

        ErrorId GetErrorId() { return  m_id; }

    private:
        std::string m_message;
        ErrorId m_id {ErrorId::Unknown};
    };

    class CodeGenerationException : public std::exception
    {
    public:
        template<typename... Args>
        CodeGenerationException(
            ErrorId id,
            Args&&... args)
        {
            m_message = GetErrorMessageById(id, std::forward<Args>(args)...);
        }

        const char* what() const noexcept override
        {
            return m_message.c_str();
        }

        private:
            std::string m_message;
    };
}
