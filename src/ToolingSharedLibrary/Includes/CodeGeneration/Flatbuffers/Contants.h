// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once 
#include <pch.h>
#include <Edl\Structures.h>

using namespace EdlProcessor;

namespace CodeGeneration::Flatbuffers
{
static inline constexpr std::string_view c_flatbuffer_compiler_name = "flatc.exe";

static inline constexpr std::string_view c_flatbuffer_compiler_default_path = "{}\\flatc.exe";

static inline constexpr std::string_view c_cpp_gen_args = "--cpp --no-prefix --cpp-std c++17 --gen-object-api --force-empty";

// Since we allow Hex inside the edl enum, we will default to uint64 to cover all scenarios.
static inline constexpr std::string_view c_enum_definition = "\nenum {} : uint64 {{\n{}}}\n";

static inline constexpr std::string_view c_table_definition = "\ntable {} {{\n{} }}\n";

static inline constexpr std::string_view c_flatbuffer_namespace = "\nnamespace FlatbuffersDevTypes;\n";

static inline constexpr std::string_view c_flatbuffer_wstring_table =
R"(
table WString {
  wchars:[int16];
}
)";

static inline constexpr std::string_view c_flatbuffer_register_callback_tables =
R"(
table AbiRegisterVtl0Callbacks_args {
  callbacks:[uint64];
  m__return_value_:int32;
}
)";

static inline constexpr std::string_view c_flatbuffer_function_context =
R"(
table {} {{
  {}
}}
)";

static inline constexpr std::string_view c_flatbuffer_fbs_filename = "vbsenclave_flatbuffer_support.fbs";

static inline std::string c_failed_to_compile_flatbuffer_msg = std::format("Compiling flatbuffer schema file: {}", c_flatbuffer_fbs_filename);

static inline std::string c_succeeded_compiling_flatbuffer_msg = std::format("Flatbuffer schema {} compiled successfuly", c_flatbuffer_fbs_filename);

static inline constexpr std::string_view c_dev_type_name = "dev_type";

static inline constexpr std::string_view c_flatbuffer_type_name = "flatbuffer";

static inline constexpr std::string_view c_flatbuffer_root_type = "\nroot_type __root_table;\n";

static inline constexpr std::string_view c_statements_for_developer_struct = "\nstruct {};\n";

static inline constexpr std::string_view c_statements_for_developer_enum = "\nenum;\n";

static inline constexpr std::string_view c_function_args_struct = "{}_args";

static inline constexpr std::string_view c_flatbuffer_root_table = R"(
table __root_table
{
}
)";
}
