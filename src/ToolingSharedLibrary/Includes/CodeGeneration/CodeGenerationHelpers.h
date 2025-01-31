// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once 
#include <pch.h>
#include <Edl\Structures.h>
#include <Edl\Utils.h>
#include <CodeGeneration\Contants.h>
#include <Exceptions.h>

using namespace EdlProcessor;
using namespace ToolingExceptions;

namespace CodeGeneration
{
    constexpr std::string_view RIGHT_ANGLE_BRACKET = ">";

    static inline std::string uint64_to_hex(uint64_t value)
    {
        std::stringstream string_stream;
        string_stream << "0x" << std::hex << value;
        return string_stream.str();
    }

    static inline std::string uint64_to_decimal(uint64_t value)
    {
        std::stringstream string_stream;
        string_stream << value; 
        return string_stream.str();
    }

    static inline std::string AddSalToParameter(
        const Declaration& declaration,
        std::string partially_complete_param)
    {
        auto& attribute_info = declaration.m_attribute_info;

        if (attribute_info)
        {
            auto& attribute = attribute_info.value();

            if (attribute.m_in_present && attribute.m_out_present)
            {
                return std::format("{} {}", c_inout_annotation, partially_complete_param);
            }
            else if (attribute.m_out_present)
            {
                return std::format("{} {}", c_out_annotation, partially_complete_param);
            }
        }
        
        // Default to using only the in annotation if none provided
        return std::format("{} {}", c_in_annotation, partially_complete_param);
    }
}
