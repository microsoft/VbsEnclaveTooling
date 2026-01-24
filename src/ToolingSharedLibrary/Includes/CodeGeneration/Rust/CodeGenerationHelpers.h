// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once 
#include <pch.h>
#include <CmdlineParsingHelpers.h>
#include <CodeGeneration\Common\Helpers.h>
#include <CodeGeneration\Rust\Constants.h>
#include <Edl\Structures.h>

using namespace EdlProcessor;
using namespace CmdlineParsingHelpers;

namespace CodeGeneration::Rust
{
    using namespace CodeGeneration::Common;

    inline bool IsStructOrWStringType(const Declaration& declaration);
    inline std::string GetParameterSyntax(const Declaration& declaration);

    inline std::string EdlTypeToRustType(const EdlTypeInfo& info, bool is_string_slice = false)
    {
        switch (info.m_type_kind)
        {
            case EdlTypeKind::UInt8:
                return "u8";
            case EdlTypeKind::UInt16:
                return "u16";
            case EdlTypeKind::UInt32:
                return "u32";
            case EdlTypeKind::Int8:
                return "i8";
            case EdlTypeKind::Int16:
                return "i16";
            case EdlTypeKind::Int32:
            case EdlTypeKind::HRESULT:
                return "i32";
            case EdlTypeKind::Int64:
                return "i64";
            case EdlTypeKind::UInt64:
            case EdlTypeKind::UIntPtr:
                return "u64";
            case EdlTypeKind::String:
                return (is_string_slice) ? "str" : "String";
            case EdlTypeKind::WString:
                return (is_string_slice) ? "U16Str" : "U16String";
            default:
                return info.m_name;
        }
    }

    inline std::string TransformCaseToUpper(const std::string& str)
    {
        std::string result(str);
        std::transform(
            result.begin(), result.end(), result.begin(),[] (char c)
            {
                return static_cast<char>(std::toupper(c));
            });

        return result;
    }

    inline std::string GetBasicRustTypeInfo(const Declaration& declaration)
    {
        if (declaration.IsEdlType(EdlTypeKind::Optional))
        {
            return std::format("Option<{}>", EdlTypeToRustType(*declaration.m_edl_type_info.inner_type));
        }
        else if (declaration.IsEdlType(EdlTypeKind::Vector))
        {
            return std::format("Vec<{}>", EdlTypeToRustType(*declaration.m_edl_type_info.inner_type));
        }
        else if (declaration.IsEdlType(EdlTypeKind::Void))
        {
            return "()";
        } 
        else if (!declaration.m_array_dimensions.empty())
        {
            auto arr_size = declaration.m_array_dimensions.front();
            auto type_name = EdlTypeToRustType(declaration.m_edl_type_info);
            return std::format(c_array_initializer, type_name, TransformCaseToUpper(arr_size));
        }

        return EdlTypeToRustType(declaration.m_edl_type_info);
    }

    inline std::string GetInnerTypeAndParameterSyntax(
        const Declaration& declaration,
        bool should_use_string_slice,
        std::string& out_inner_type_name)
    {
        auto inner_type = declaration.m_edl_type_info.inner_type;
        out_inner_type_name = EdlTypeToRustType(*inner_type, should_use_string_slice);
        return GetParameterSyntax(declaration);
    }
    inline std::string AddVectorEncapulation(const Declaration& vector_declaration)
    {
        std::string inner_type_name;
        auto param_syntax = GetInnerTypeAndParameterSyntax(vector_declaration, false, inner_type_name);

        if (vector_declaration.IsInParameterOnly())
        {
            // For in parameters, we use a slice.
            return std::format("{} : {}[{}]", vector_declaration.m_name, param_syntax, inner_type_name);
        }

        return std::format("{} : {}Vec<{}>", vector_declaration.m_name, param_syntax, inner_type_name);
    }

    inline std::string AddOptionalEncapulation(const Declaration& optional_declaration)
    {
        std::string inner_type_name;
        auto param_syntax = GetInnerTypeAndParameterSyntax(
            optional_declaration, 
            optional_declaration.IsInParameterOnly(), 
            inner_type_name);

        // For in parameters that are optional, we use Option<T> or Option<&T>/Option<&mut T> if a borrow is needed.
        return std::format("{} : Option<{}{}>", optional_declaration.m_name, param_syntax, inner_type_name);
    }

    inline std::string GetParameterForFunction(const Declaration& declaration)
    {
        if (declaration.IsEdlType(EdlTypeKind::Optional))
        {
            return AddOptionalEncapulation(declaration);
        }

        if (declaration.IsEdlType(EdlTypeKind::Vector))
        {
            return AddVectorEncapulation(declaration);
        }

        auto param_syntax = GetParameterSyntax(declaration);
        
        if (!declaration.m_array_dimensions.empty())
        {
            auto arr_size = declaration.m_array_dimensions.front();
            std::string type_name = EdlTypeToRustType(declaration.m_edl_type_info, false);
            type_name = std::format(c_array_initializer, type_name, TransformCaseToUpper(arr_size));
            return std::format("{} : {}{}", declaration.m_name, param_syntax, type_name);
        }

        std::string type_name = EdlTypeToRustType(declaration.m_edl_type_info, declaration.IsInParameterOnly());
        return std::format("{} : {}{}", declaration.m_name, param_syntax, type_name);
    }

    inline std::string GetParameterSyntax(const Declaration& declaration)
    {
        // Primitive in parameters should not have a borrow declarator.
        if (declaration.IsInParameterOnly() && declaration.IsPrimitiveType())
        {
            return {};
        }

        // Mutable borrow.
        if (declaration.IsInOutParameter() || declaration.IsOutParameter())
        {
            return "&mut ";
        }

        // Const borrow for all other parameters.
        return "&";
    }

    inline std::string GetEnumValueExpression(const EnumType& enum_value)
    {
        if (enum_value.m_value)
        {
            // Value was explicitly assigned
            return enum_value.m_value.value();
        }

        if (enum_value.m_is_hex)
        {
            return Uint64ToHex(enum_value.m_declared_position);
        }

        return Uint64ToDecimal(enum_value.m_declared_position);
    }

    inline std::string GenerateConstantsFromAnonEnum(const DeveloperType& developer_types)
    {
        std::ostringstream pub_constants {};
        for (auto& enum_value : developer_types.m_items.values())
        {
            // Rust expects constants to be all uppercased
            pub_constants << std::format(
                "\npub const {}: usize = {};",
                TransformCaseToUpper(enum_value.m_name),
                GetEnumValueExpression(enum_value)
            );
        }
        return pub_constants.str();
    }

    inline std::string GenerateFunctionParametersList(const std::vector<Declaration>& parameters)
    {
        std::ostringstream parameter_list {};
        for (auto i = 0U; i < parameters.size(); i++)
        {
            parameter_list << GetParameterForFunction(parameters[i]);
            if (i < parameters.size() - 1)
            {
                parameter_list << ", ";
            }
        }
        return parameter_list.str();
    }

    inline std::string GetCloneToAbiStructStatements(
        uint32_t indentation,
        const std::vector<Declaration>& parameters)
    {
        std::ostringstream abi_struct_fill_statements {};
        auto tabs = GenerateTabs(indentation);
        for (auto& param : parameters)
        {
            // Out-only parameters are written back separately.
            if (param.IsOutParameterOnly())
            {
                continue;
            }

             // Arrays are cloned verbatim.
            if (!param.m_array_dimensions.empty())
            {
                abi_struct_fill_statements << std::format(
                    "{}abi_type.m_{} = {}.clone();\n",
                    tabs,
                    param.m_name,
                    param.m_name);

                continue;
            }

             // Vectors require ownership transfer.
            if (param.IsEdlType(EdlTypeKind::Vector))
            {
                abi_struct_fill_statements << std::format(
                    "{}abi_type.m_{} = {}.to_owned();\n",
                    tabs,
                    param.m_name,
                    param.m_name);

                continue;
            }

            // Strings require explicit allocation.
            if (param.IsEdlType(EdlTypeKind::String) ||
                param.IsEdlType(EdlTypeKind::WString))
            {
                auto func = param.IsEdlType(EdlTypeKind::String)
                    ? ".to_string()"
                    : ".to_ustring()";

                abi_struct_fill_statements << std::format(
                    "{}abi_type.m_{} = {}{};\n",
                    tabs,
                    param.m_name,
                    param.m_name,
                    func);

                continue;
            }

            // Optional<T> requires cloning or copying the inner value.
            if (param.IsEdlType(EdlTypeKind::Optional))
            {
                if (param.IsInnerEdlType(EdlTypeKind::String) ||
                    param.IsInnerEdlType(EdlTypeKind::WString))
                {
                    const char* func = param.IsInnerEdlType(EdlTypeKind::String)
                        ? "map(String::from)"
                        : "map(widestring::U16String::from)";

                    abi_struct_fill_statements << std::format(
                        "{}abi_type.m_{} = {}.{};\n",
                        tabs,
                        param.m_name,
                        param.m_name,
                        func);
                }
                else
                {
                    auto inner = param.m_edl_type_info.inner_type;
                    bool is_primitive = c_edlTypes_primitive_set.contains(inner->m_type_kind);

                    abi_struct_fill_statements << std::format(
                        "{}abi_type.m_{} = {}.as_deref().{}();\n",
                        tabs,
                        param.m_name,
                        param.m_name,
                        is_primitive ? "copied" : "cloned");
                }

                continue;
            }

            // Fallback: clone everything else.
            abi_struct_fill_statements << std::format(
                "{}abi_type.m_{} = {}.clone();\n",
                tabs,
                param.m_name,
                param.m_name);
        }

        return abi_struct_fill_statements.str();
    }

    inline std::string GetMoveFromAbiStructToParamStatements(
        uint32_t indentation,
        std::string_view parent_crate,
        const std::vector<Declaration>& parameters)
    {
        std::ostringstream param_update_statements {};
        auto tabs = GenerateTabs(indentation);
        for (auto& param : parameters)
        {
            if (param.IsInParameterOnly())
            {
                continue;
            }

            bool is_array = !param.m_array_dimensions.empty();

            // For struct and wstring out-parameters, the ABI uses Option<T> because
            // FlatBuffers represents non-required table fields that way. Even though the .edl
            // signature declares an out parameter of type T, we must unwrap the
            // Option<T> here to satisfy the ABI contract. This value is expected to
            // always be present; encountering None indicates a bug in the flatbuffer to ABI type
            // layer.
            if (!is_array && param.IsOutParameterOnly() && IsStructOrWStringType(param))
            {
                param_update_statements << std::format(
                    "{}*{} = result.m_{}.expect(\"Unexpected empty Option: m_{}\");\n",
                    tabs,
                    param.m_name,
                    param.m_name,
                    param.m_name);
            }
            // For optional out and inout parameters, we need to use the assign_if_some helper
            // to only update the parameter if the ABI provided a value.
            else if (param.IsInOutOrOutParameter() && param.IsEdlType(EdlTypeKind::Optional))
            {
                param_update_statements << std::format(
                    "{}{}::assign_if_some({}, result.m_{});\n",
                    tabs,
                    parent_crate,
                    param.m_name,
                    param.m_name);
            }
            else
            {
                // Fallback: direct move assignment.
                param_update_statements << std::format("{}*{} = result.m_{};\n", tabs, param.m_name, param.m_name);
            }
        }

        return param_update_statements.str();
    }

    inline bool IsStructOrWStringType(const Declaration& declaration)
    {
        return declaration.IsEdlType(EdlTypeKind::Struct) ||
               declaration.IsEdlType(EdlTypeKind::WString);
    }

    inline std::string GetClosureFunctionStatement(
        const Function& function,
        VirtualTrustLayerKind vtl_kind)
    {
        std::ostringstream abi_struct_fields {};
        for (auto i = 0U; i < function.m_parameters.size(); i++)
        {
            Declaration param = function.m_parameters[i];

            bool is_array = !param.m_array_dimensions.empty();

            // Out-only struct / wstring params are Option<T> in the ABI; unwrap to get &mut T.
            // None here indicates an ABI-layer bug.
            if (!is_array && param.IsOutParameterOnly() && IsStructOrWStringType(param))
            {
                abi_struct_fields << std::format(
                    "abi_type.m_{}.as_mut().expect(\"Unexpected empty Option: m_{}\")",
                    param.m_name,
                    param.m_name);
            }
            // Optional<T>: project to the appropriate borrowed form based on direction and inner type.
            else if (param.IsEdlType(EdlTypeKind::Optional))
            {
                std::string func {};

                if (param.IsInnerEdlType(EdlTypeKind::String) ||
                    param.IsInnerEdlType(EdlTypeKind::WString))
                {
                    // in parameter of optional string/wstring are mapped as Option<&str> / Option<&U16Str>
                    // and out/inout as Option<&mut String> / Option<&mut U16String>
                    func = param.IsInParameterOnly() ? "as_deref()" : "as_mut()";
                }
                else
                {
                    // in parameter of other optional types are mapped as Option<&T> and out/inout as Option<&mut T>
                    func = param.IsInParameterOnly() ? "as_ref()" : "as_mut()";
                }

                abi_struct_fields << std::format(
                    "abi_type.m_{}.{}",
                    param.m_name,
                    func);
            }
            // All other parameters are passed through directly with appropriate borrowing.
            else
            {
                abi_struct_fields << std::format("{}abi_type.m_{}", GetParameterSyntax(param), param.m_name);
            }

            if (i < function.m_parameters.size() - 1)
            {
                abi_struct_fields << ", ";
            }
        }

        bool returns_void = function.m_return_info.IsEdlType(EdlTypeKind::Void);

        if (returns_void && vtl_kind == VirtualTrustLayerKind::HostApp)
        {
            return std::format(c_host_closure_content_no_result, function.m_name, abi_struct_fields.str());

        }
        else if (IsStructOrWStringType(function.m_return_info) && vtl_kind == VirtualTrustLayerKind::HostApp)
        {
            return std::format(c_host_closure_content_with_some, function.m_name, abi_struct_fields.str());
        }
        else if (vtl_kind == VirtualTrustLayerKind::HostApp)
        {
            return std::format(c_host_closure_content_with_result, function.m_name, abi_struct_fields.str());
        }

        if (returns_void)
        {
            return std::format(c_enclave_closure_content_no_result, function.m_name, abi_struct_fields.str());
        }
        else if (IsStructOrWStringType(function.m_return_info))
        {
            return std::format(c_enclave_closure_content_with_some, function.m_name, abi_struct_fields.str());
        }

        return std::format(c_enclave_closure_content_with_result, function.m_name, abi_struct_fields.str());
    }

    struct EdlCrateInfo
    {
        std::string m_crate_name {};
        std::string m_alloc_imports {};
        std::string m_vec_import {};
    };

    inline EdlCrateInfo GetEdlCrateInfo(VirtualTrustLayerKind vtl_kind)
    {
        EdlCrateInfo crate_info {};
        if (vtl_kind == VirtualTrustLayerKind::Enclave)
        {
            crate_info.m_crate_name = "edlcodegen_enclave";
            crate_info.m_alloc_imports = c_enclave_alloc_imports.data();
            crate_info.m_vec_import = c_enclave_vec_import.data();
        }
        else
        {
            crate_info.m_crate_name = "edlcodegen_host";
        }
        return crate_info;
    }

    inline std::tuple<std::string,std::string, std::string> GetRegisterCallbacksFunctionStatements(
        const OrderedMap<std::string, Function>& functions)
    {
        std::ostringstream callback_names {};
        callback_names << "\"VbsEnclaveABI::HostApp::AllocateVtl0MemoryCallback\",";
        callback_names << "\"VbsEnclaveABI::HostApp::DeallocateVtl0MemoryCallback\",";
        std::ostringstream callback_addresses {};
        callback_addresses << "abi_func_to_address(edlcodegen_host::allocate_memory_ffi),";
        callback_addresses << "abi_func_to_address(edlcodegen_host::deallocate_memory_ffi),";
        for (auto& func : functions.values())
        {
            auto generated_stub_name = std::format(c_generated_stub_name_no_quotes, func.abi_m_name);
            std::string callbacks_name_with_quotes = std::format("\"{}\",", generated_stub_name);
            callback_names << callbacks_name_with_quotes;
            callback_addresses << std::format("abi_func_to_address(Self::{}), ", generated_stub_name);
        }

        auto total = std::format("{}", functions.size() + 2);
        return {callback_names.str(), callback_addresses.str(), total};
    }
}
