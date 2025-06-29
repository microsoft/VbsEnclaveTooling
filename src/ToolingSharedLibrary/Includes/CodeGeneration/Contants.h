// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#pragma once 
#include <pch.h>
#include <Edl\Structures.h>

using namespace EdlProcessor;

namespace CodeGeneration
{
    static inline constexpr std::string_view c_four_spaces = "    ";

    static inline constexpr std::string_view c_developer_types_header = "DeveloperTypes.h";

    static inline constexpr std::string_view c_trust_vtl1_stubs_header = "Stubs.cpp";

    static inline constexpr std::string_view c_untrusted_vtl0_stubs_header = "Stubs.h";

    static inline constexpr std::string_view c_trusted_vtl1_impl_header = "Implementations.h";

    static inline constexpr std::string_view c_enclave_exports_source = "{}_Exports.cpp";

    static inline constexpr std::string_view c_output_folder_for_generated_trusted_functions = R"(VbsEnclave\Enclave)";

    static inline constexpr std::string_view c_output_folder_for_generated_untrusted_functions = R"(VbsEnclave\HostApp)";

    static inline constexpr std::string_view c_abi_boundary_func_declaration = "    __declspec(dllexport) void* {}(void* function_context);\n";

    static inline constexpr std::string_view c_abi_boundary_func_declaration_for_stubs = "        void* {}(void* function_context);\n";

    static inline constexpr std::string_view c_stubs_header_for_enclave_exports = "{}_StubsForExports.h";

    static inline constexpr std::string_view c_autogen_header_string =
R"(// This file was auto-generated by edlcodegen.exe
// Changes to this file may be lost if the file is regenerated.
)";

    static inline constexpr std::string_view c_array_initializer = "std::array<{}, {}>";

    static inline constexpr std::string_view c_in_annotation = "_In_";

    static inline constexpr std::string_view c_inout_annotation = "_Inout_";

    static inline constexpr std::string_view c_out_annotation = "_Out_";

    static inline constexpr std::string_view c_return_variable_name = "result";

    static inline constexpr std::string_view c_generated_stub_name = "\"{}_Generated_Stub\"";

    static inline constexpr std::string_view c_generated_stub_name_no_quotes = "{}_Generated_Stub";

    // Using a R("...") that contains a " character with std::format ends up adding a \" to the string.
    // instead of the double quote itself. So, as a work around we'll use the old style of declaring a multi line string.
    static inline constexpr std::string_view c_vtl0_class_start_of_file = 
"\
#pragma once\n\
#include <VbsEnclaveABI\\Host\\HostHelpers.h>\n\
#include \"DeveloperTypes.h\"\
\n\
using namespace VbsEnclaveABI;\n\
using namespace VbsEnclaveABI::Shared;\n\
using namespace VbsEnclaveABI::HostApp;\n\
using namespace DeveloperTypes;\n\
\n\
";

    static inline constexpr std::string_view c_vtl0_class_hostapp_namespace = R"(
namespace {}
{{
    namespace VTL0_Stubs
    {{
        using namespace VbsEnclaveABI::Shared::Converters;

        {}
    }}
}}
)";

    // Using a R("...") that contains a " character with std::format ends up adding a \" to the string.
    // instead of the double quote itself. So, as a work around we'll use the old style of declaring a multi line string.
    static inline constexpr std::string_view c_vtl1_enclave_stub_includes = 
"\
#pragma once\n\
#include <VbsEnclaveABI\\Enclave\\EnclaveHelpers.h>\n\
#include \"Implementations.h\"\n\
\n\
using namespace VbsEnclaveABI;\n\
using namespace VbsEnclaveABI::Shared;\n\
using namespace VbsEnclaveABI::Enclave;\n\
using namespace DeveloperTypes;\n\
\n\
";

    static inline constexpr std::string_view c_vtl1_enclave_stub_namespace = R"(
namespace {}
{{
    namespace VTL1_Stubs
    {{
        static void EnforceMemoryRestriction()
        {{
            if (ENABLE_ENCLAVE_RESTRICT_CONTAINING_PROCESS_ACCESS)
            {{
                EnableEnclaveRestrictContainingProcessAccessOnce();
            }}
        }}
    {}
    }}
}}
)";

    static inline constexpr std::string_view c_enforce_memory_restriction_call =
        R"(EnforceMemoryRestriction();)";

    static inline constexpr std::string_view c_outer_abi_function = R"(
        {} {}_Generated_Stub(void* function_context)
        try
        {{
            {}
            LOG_IF_FAILED(hr);
            return ABI_HRESULT_TO_PVOID(hr);
        }}
        catch (...)
        {{
            HRESULT hr = wil::ResultFromCaughtException();
            LOG_IF_FAILED(hr);
            return ABI_HRESULT_TO_PVOID(hr);
        }}
)";

    // This body is specific to the developer function
    static inline constexpr std::string_view c_inner_abi_function =
        R"(using ParamsT = FlatbuffersDevTypes::{}T;
            using ReturnParamsT = FlatbuffersDevTypes::{}T;
            {}
            {})";

    // This body is specific to the developer function
    static inline constexpr std::string_view c_initial_caller_function_body = R"(
        {}
        {{
            {}
            auto function_result = ReturnParamsT();
            {}
            {}
        }}
)";

    static inline constexpr std::string_view c_vtl0_call_to_vtl1_export =
 R"(THROW_IF_FAILED((CallVtl1ExportFromVtl0<ReturnParamsT>(m_enclave, {}, flatbuffer_builder, function_result)));)";

    static inline constexpr std::string_view c_vtl1_call_to_vtl1_export =
 R"(HRESULT hr = CallVtl1ExportFromVtl1<ParamsT, decltype(AbiDefinitions::{}_Abi_Impl)>(function_context, AbiDefinitions::{}_Abi_Impl);)";

    static inline constexpr std::string_view c_vtl0_call_to_vtl0_callback =
 R"(HRESULT hr = CallVtl0CallbackImplFromVtl0<ParamsT, ReturnParamsT, decltype({}_Abi_Impl)>(function_context, {}_Abi_Impl);)";

    static inline constexpr std::string_view c_vtl1_call_to_vtl0_callback =
 R"(THROW_IF_FAILED((CallVtl0CallbackFromVtl1<ParamsT, ReturnParamsT>({}, flatbuffer_builder, function_result)));)";

    static inline constexpr std::string_view c_generated_callback_in_namespace = "\"{}::{}::{}_Generated_Stub\"";

    // Using a R("...") that contains a " character with std::format ends up adding a \" to the string.
    // instead of the double quote itself. So, as a work around we'll use the old style of declaring a multi line string.
    static inline constexpr std::string_view c_vtl1_enclave_func_impl_start_of_file =
"\
#pragma once\n\
#include <VbsEnclaveABI\\Enclave\\EnclaveHelpers.h>\n\
#include \"DeveloperTypes.h\"\n\
\n\
using namespace VbsEnclaveABI;\n\
using namespace VbsEnclaveABI::Shared;\n\
using namespace VbsEnclaveABI::Enclave;\n\
using namespace DeveloperTypes;\n\
\n\
";

    static inline constexpr std::string_view c_vtl1_sdk_pragma_statement = R"(#pragma comment(linker, "/include:{}")
)";

    static inline constexpr std::string_view c_vtl1_export_functions_source_file =
"\
{}\n\
#pragma once\n\
#include \"{}_StubsForExports.h\"\n\
\n\
// Explicitly add linker statements so the generated export functions created by the code generator \n\
// can be exported when used to create a static lib.\n\
{}{}\n\
";

    static inline constexpr std::string_view c_enclave_export_func_definition = R"(
extern "C" __declspec(dllexport) void* {}(void* function_context) 
{{
    return {}::VTL1_Stubs::{}(function_context);
}}
)";

    static inline constexpr std::string_view c_vtl1_export_stub_declarations_header =
"\
{}\n\
#pragma once\n\
\n\
namespace {}\n\
{{\n\
    namespace VTL1_Stubs\n\
    {{\n\
{}\n\
    }}\n\
}}\n\
";


    static inline constexpr std::string_view c_vtl1_enclave_func_impl_namespace = R"(
namespace {}
{{
    namespace VTL1_Declarations
    {{
        {}
    }}

    namespace VTL0_Callbacks
    {{
        using namespace VbsEnclaveABI::Shared::Converters;

        {}
    }}

    namespace AbiDefinitions
    {{
        using namespace VbsEnclaveABI::Shared::Converters;

        {}
    }}
}}
)";

    // Using a R("...") that contains a " character with std::format ends up adding a \" to the string.
    // instead of the double quote itself. So, as a work around we'll use the old style of declaring a multi line string.
    static inline constexpr std::string_view c_developer_types_start_of_file = 
"\
{}\n\
#pragma once\n\
#include <VbsEnclaveABI\\Shared\\VbsEnclaveAbiBase.h>\n\
#undef max // prevent windows max macro from conflicting with flatbuffers macro\n\
#include \"vbsenclave_flatbuffer_support_generated.h\"\n\
#include <VbsEnclaveABI\\Shared\\ConversionHelpers.h>\n\
\n\
";

    static inline constexpr std::string_view c_developer_types_namespace = R"(
namespace DeveloperTypes
{{
{}
}}

// Struct metadata
namespace VbsEnclaveABI::Shared::Converters
{{
{}
}}
)";

    static inline constexpr std::string_view c_enclave_def_file_content = R"(
{}
LIBRARY

    EXPORTS
{}
)";

    static inline constexpr std::string_view c_vtl0_class_constructor = 
R"({}(LPVOID enclave) : m_enclave(enclave)
            {{
            }}
)";

    static inline constexpr std::string_view c_vtl0_class_add_callback_member = R"(
        private:
            LPVOID m_enclave{{}};
            bool m_callbacks_registered{{}};
            wil::srwlock m_register_callbacks_lock{{}};
            std::array<uintptr_t, {}> m_callback_addresses{{ {} }};
            std::array<std::string, {}> m_callback_names{{ {} }};
)";

    static inline constexpr std::string_view c_vtl1_register_callback_function = "VTL0CallBackHelpers::AddVtl0FunctionsToTable";

    static inline constexpr std::string_view c_generated_abi_impl_function = R"(
        static inline void {}_Abi_Impl{}
        {{
            {}
        }}
)";

    static inline constexpr std::string_view c_allocate_memory_callback_to_address = "reinterpret_cast<uintptr_t>(&VbsEnclaveABI::HostApp::AllocateVtl0MemoryCallback)";

    static inline constexpr std::string_view c_deallocate_memory_callback_to_address = ",reinterpret_cast<uintptr_t>(&VbsEnclaveABI::HostApp::DeallocateVtl0MemoryCallback)";

    static inline constexpr std::string_view c_allocate_memory_callback_to_name = "\"VbsEnclaveABI::HostApp::AllocateVtl0MemoryCallback\"";

    static inline constexpr std::string_view c_deallocate_memory_callback_to_name = ",\"VbsEnclaveABI::HostApp::DeallocateVtl0MemoryCallback\"";

    static inline constexpr std::string_view c_callback_to_address = ", reinterpret_cast<uintptr_t>(&{}_Generated_Stub)";

    static inline constexpr std::string_view c_callback_to_name = ", {}";

    static inline constexpr std::string_view c_untrusted_function_name = "{}_callback";

    static inline constexpr std::string_view c_exported_function_in_module = 
R"(     {}_Generated_Stub
)";

    static inline constexpr size_t c_number_of_abi_callbacks = 2;

    static inline constexpr std::string_view c_vtl0_enclave_class_name = "{}Wrapper";

    static inline constexpr std::string_view c_vtl0_enclave_class_public_keyword = R"(
        public:
)";

    static inline constexpr std::string_view c_vtl0_enclave_class_private_keyword = R"(
        private:
)";

    static inline constexpr std::string_view c_void_ptr = "void*";

    static inline constexpr std::string_view c_static_void_ptr = "static inline void*";

    static inline constexpr std::string_view c_static_declaration = R"(
        static {} {}{};
)";

    static inline constexpr std::string_view c_function_declaration = R"(
        {} {}{};
)";

    static inline constexpr std::string_view c_static_keyword = "static ";

    static inline constexpr std::string_view c_vtl0_abi_boundary_functions_comment = R"(
        /***********************************************
         *    VTL0 Generated ABI Boundary Callbacks    *
        ************************************************/
        )";

    static inline constexpr std::string_view c_vtl1_abi_boundary_functions_comment = R"(
        /***********************************************
         *    VTL1 Generated ABI Boundary Callbacks    *
        ************************************************/
        )";

    static inline constexpr std::string_view c_vtl0_abi_impl_callback_functions_comment = R"(
        /*****************************************************
         *    VTL0 Generated ABI Implementation Callbacks    *
        ******************************************************/
        )";

    static inline constexpr std::string_view c_vtl1_abi_impl_functions_comment = R"(
        /*****************************************************
         *    VTL0 Generated ABI Implementation Callbacks    *
        ******************************************************/
        )";

    static inline constexpr std::string_view c_vtl0_developer_declaration_functions_comment = R"(
        /*****************************************************
         *    VTL0 Generated Developer Method Declarations   *
        ******************************************************/
        )";

    static inline constexpr std::string_view c_vtl1_developer_declaration_functions_comment = R"(
        /*******************************************************
         *    VTL1 Generated Developer Function Declarations   *
        ********************************************************/
        )";

    static inline constexpr std::string_view c_vtl0_side_of_vtl1_developer_impl_functions_comment = R"(
        /************************************************************
         *    VTL0 Side Of VTL1 Developer Function Implementations  *
        *************************************************************/
        )";

    static inline constexpr std::string_view c_vtl1_side_of_vtl0_developer_callback_functions_comment = R"(
        /**********************************************************
         *    VTL1 Side Of VTL0 Developer Method Implementations  *
        ***********************************************************/
)";

    static inline constexpr std::string_view c_vtl0_register_callbacks_abi_function = R"(
        HRESULT RegisterVtl0Callbacks()
        {{
            auto lock = m_register_callbacks_lock.lock_exclusive();

            if (m_callbacks_registered)
            {{
                return S_OK;
            }}

            FlatbuffersDevTypes::AbiRegisterVtl0Callbacks_argsT input {{}};
            input.callback_addresses.assign(m_callback_addresses.begin(), m_callback_addresses.end());
            input.callback_names.assign(m_callback_names.begin(), m_callback_names.end());
            flatbuffers::FlatBufferBuilder builder = PackFlatbuffer(input);
            using ReturnParamsT = FlatbuffersDevTypes::AbiRegisterVtl0Callbacks_argsT;
            ReturnParamsT out_args {{}};

            HRESULT hr = CallVtl1ExportFromVtl0<ReturnParamsT>(
                m_enclave,
                {},
                builder,
                out_args);
            RETURN_IF_FAILED(hr);

            if (SUCCEEDED(out_args.m__return_value_))
            {{
                m_callbacks_registered = true;
            }}

            return out_args.m__return_value_;
        }}
)";

    static inline constexpr std::string_view c_vtl1_register_callbacks_abi_export_name = "__AbiRegisterVtl0Callbacks_{}__";

    static inline constexpr std::string_view c_vtl1_register_callbacks_abi_export = R"(
        void RegisterVtl0Callbacks(
            _In_ FlatbuffersDevTypes::AbiRegisterVtl0Callbacks_argsT in_params,
            _Inout_ flatbuffers::FlatBufferBuilder& flatbuffer_out_params_builder)
        {{
            THROW_IF_FAILED(AddVtl0FunctionsToTable(in_params.callback_addresses, in_params.callback_names));

            FlatbuffersDevTypes::AbiRegisterVtl0Callbacks_argsT  result{{}};
            result.m__return_value_ = S_OK;

            flatbuffer_out_params_builder = PackFlatbuffer(result);
        }}

        void* {}(void* function_context)
        try
        {{
            EnforceMemoryRestriction();
            using ParamsT = FlatbuffersDevTypes::AbiRegisterVtl0Callbacks_argsT;
            HRESULT hr = CallVtl1ExportFromVtl1<ParamsT, decltype(RegisterVtl0Callbacks)>(function_context, RegisterVtl0Callbacks);
            LOG_IF_FAILED(hr);
            return ABI_HRESULT_TO_PVOID(hr);
        }}
        catch (...)
        {{
            HRESULT hr = wil::ResultFromCaughtException();
            LOG_IF_FAILED(hr);
            return ABI_HRESULT_TO_PVOID(hr);
        }}
)";

    static inline constexpr std::string_view c_vtl0_class_structure =
        R"({}
        {}
            {}
            {}
            {}
        {}
)";

    static inline constexpr std::string_view c_dev_type_for_developer_struct = "dev_type_params";

    static inline constexpr std::string_view c_dev_type_for_function_params_struct = "dev_type_params";

    static inline constexpr std::string_view c_update_inout_and_out_param_statement = "            UpdateParameterValue(return_params.m_{}, {});\n";

    static inline constexpr std::string_view c_parameter_struct_using_statement =
R"(             using ReturnParamsT = FlatbuffersDevTypes::{}T;)";

    static inline constexpr std::string_view c_parameter_conversion_statement =
"            in_flatbufferT.m_{} = ConvertType<decltype(in_flatbufferT.m_{})>({});\n";

    static inline constexpr std::string_view c_pack_params_to_flatbuffer_call =
R"(// Package in and in/out parameters into struct and convert it to a flatbuffer type.
            FlatbuffersDevTypes::{}T in_flatbufferT {{}};
{}
            using ParamsT = decltype(in_flatbufferT);
            auto flatbuffer_builder = PackFlatbuffer(in_flatbufferT);
    )";

    static inline constexpr std::string_view c_abi_impl_function_parameters = "(_In_ FlatbuffersDevTypes::{}_argsT& in_flatbuffer_params, _In_ flatbuffers::FlatBufferBuilder& flatbuffer_out_params_builder)";

    static inline constexpr std::string_view c_instantiate_dev_type =
R"({} dev_type_params{{}};
)";

    static inline constexpr std::string_view c_conversion_to_dev_type_statement =
R"(auto dev_type_params = ConvertStruct<{}>(in_flatbuffer_params);
)";

    static inline constexpr std::string_view c_abi_func_return_value =
R"(            dev_type_params.m__return_value_ = {}({});
{})";

    static inline constexpr std::string_view c_abi_func_return_when_void =
R"({}({});
{})";

    static inline constexpr std::string_view c_setup_return_params_struct = R"(
            auto flatbuffer_out_param = ConvertStruct<decltype(in_flatbuffer_params)>(dev_type_params);
            flatbuffer_out_params_builder = PackFlatbuffer(flatbuffer_out_param);)";

    static inline constexpr std::string_view c_setup_no_return_params_struct = R"(
            flatbuffer_out_params_builder = PackFlatbuffer<FlatbuffersDevTypes::{}T>({{}});)";

    static inline constexpr std::string_view c_setup_return_params_back_to_developer = R"(
            auto return_params = ConvertStruct<{}>(function_result);
{}
)";

    static inline constexpr std::string_view c_return_value_back_to_initial_caller_with_move =
R"(            return std::move(return_params.m__return_value_);)";

    static inline constexpr std::string_view c_parameter_return_struct_using_statement =
R"(        using ReturnParamsT = FlatbuffersDevTypes::{}T;)";

    static inline constexpr std::string_view c_function_args_struct = "{}_args";

    static inline constexpr std::string_view c_struct_metadata_field_ptr = "&DeveloperTypes::{}::{}{}";

    static inline constexpr std::string_view c_flatbuffer_field_ptr = "&FlatbuffersDevTypes::{}T::{}{}";

    static inline constexpr std::string_view c_struct_meta_data_outline = 
R"(
template <>
struct StructMetadata<{}>
{{
    static constexpr auto members = std::make_tuple({});
}};
)";
}

