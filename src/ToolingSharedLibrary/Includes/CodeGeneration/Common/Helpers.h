// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once 
#include <pch.h>
#include <Edl\Structures.h>
#include <Edl\Utils.h>
#include <Exceptions.h>
#include <fstream>
#include <CodeGeneration\Common\Constants.h>
#include <CodeGeneration\Cpp\Constants.h>
#include <CodeGeneration\Flatbuffers\Constants.h>

using namespace CodeGeneration::Flatbuffers;
using namespace EdlProcessor;
using namespace ToolingExceptions;

namespace CodeGeneration::Common
{
    static size_t c_type_definition_tab_count = 1;

    inline std::string Uint64ToHex(uint64_t value)
    {
        std::stringstream string_stream;
        string_stream << "0x" << std::hex << value;
        return string_stream.str();
    }

    inline std::string Uint64ToDecimal(uint64_t value)
    {
        std::stringstream string_stream;
        string_stream << value;
        return string_stream.str();
    }

    void inline InvokeFlatbufferCompiler(const std::filesystem::path& compiler_path, std::string_view args)
    {
        PrintStatus(Status::Info, Flatbuffers::c_failed_to_compile_flatbuffer_msg.data());
        std::string complete_argument = std::format("{} {}", compiler_path.generic_string(), args);
        auto result = std::system(complete_argument.c_str());

        if (result)
        {
            // The flatbuffer compiler prints out the actual error message to stdout.
            throw CodeGenerationException(ErrorId::FlatbufferCompilerError, result);
        }

        PrintStatus(Status::Info, Flatbuffers::c_succeeded_compiling_flatbuffer_msg.data());
    }

    inline DeveloperType GetDeveloperTypeStructForABI(const Function& function)
    {
        std::string function_params_struct_type = std::format(c_function_args_struct, function.abi_m_name);
        DeveloperType new_type {function_params_struct_type, EdlTypeKind::Struct};

        // Add all parameters to the struct as fields first.
        for (Declaration parameter : function.m_parameters)
        {
            parameter.m_name = "m_" + parameter.m_name;
            parameter.m_parent_kind = DeclarationParentKind::Struct;
            new_type.m_fields.push_back(parameter);
        }

        // Add the return type as the last field in the struct if the function does not return void.
        if (!function.m_return_info.IsEdlType(EdlTypeKind::Void))
        {
            auto return_copy = function.m_return_info;
            return_copy.m_name = "m_" + return_copy.m_name;
            return_copy.m_parent_kind = DeclarationParentKind::Struct;
            new_type.m_fields.push_back(return_copy);
        }

        return new_type;
    }

    inline std::vector<DeveloperType> CreateDeveloperTypesForABIFunctions(
        const OrderedMap<std::string, Function>& trusted_functions,
        const OrderedMap<std::string, Function>& untrusted_functions)
    {
        std::vector<DeveloperType> dev_types {};

        for (auto& function : trusted_functions.values())
        {
            DeveloperType dev_type = GetDeveloperTypeStructForABI(function);
            dev_types.push_back(dev_type);
        }

        for (const auto& function : untrusted_functions.values())
        {
            DeveloperType dev_type = GetDeveloperTypeStructForABI(function);
            dev_types.push_back(dev_type);
        }

        return dev_types;
    }

    // std::format in C++20 requires the "format_string" to be known at compile time. 
    // this is used for instances where we only know the format string at runtime.
    template<typename... Args>
    inline std::string FormatString(std::string_view format_string, Args&&... args)
    {
        return std::vformat(format_string, std::make_format_args(args...));
    }

    inline std::string GenerateTabs(std::size_t count)
    {
        // Use 4 spaces as tabs
        std::string spaces{};
        while (count > 0)
        {
            spaces += c_four_spaces;
            count--;
        }

        return spaces;
    }

    inline void SaveFileToOutputFolder(
        std::string_view file_name,
        const std::filesystem::path& output_folder,
        std::string_view file_content)
    {
        auto output_file_path = output_folder / file_name;

        if (!std::filesystem::exists(output_folder) && !std::filesystem::create_directories(output_folder))
        {
            throw CodeGenerationException(
                ErrorId::CodeGenUnableToOpenOutputFile,
                output_file_path.generic_string());
        }

        std::ofstream output_file(output_file_path.generic_string());

        if (output_file.is_open())
        {
            output_file << file_content;
            output_file.close();
        }
        else
        {
            throw CodeGenerationException(
                ErrorId::CodeGenUnableToOpenOutputFile,
                output_file_path.generic_string());
        }
    }

    inline void CompileFlatbufferFile(
        std::filesystem::path compiler_path,
        std::string_view args,
        std::filesystem::path save_location)
    {
        auto flatbuffer_schema_path = (save_location / c_flatbuffer_fbs_filename).generic_string();

        std::string flatbuffer_args = std::format(R"({} -o "{}" "{}")", args, save_location.generic_string(), flatbuffer_schema_path);
        InvokeFlatbufferCompiler(compiler_path, flatbuffer_args);
    }
}
