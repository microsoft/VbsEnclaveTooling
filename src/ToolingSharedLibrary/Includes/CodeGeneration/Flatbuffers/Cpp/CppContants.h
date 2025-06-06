// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once 
#include <pch.h>

using namespace EdlProcessor;

namespace CodeGeneration::Flatbuffers::Cpp
{
    static inline constexpr std::string_view c_using_statements_for_developer_struct = "\nstruct {};\n";

    static inline constexpr std::string_view c_using_statements_for_developer_enum = "\nenum;\n";

    static inline constexpr std::string_view c_params_struct = "dev_type_params";
}
