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

    inline std::string EdlTypeToRustType(const EdlTypeInfo& info)
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
                return "String";
            case EdlTypeKind::WString:
                return "edl::WString";
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

    inline std::string AddVectorEncapulation(const Declaration& vector_declaration)
    {
        auto inner_type = vector_declaration.m_edl_type_info.inner_type;
        auto inner_type_name = EdlTypeToRustType(*inner_type);
        return std::format("Vec<{}>", inner_type_name);
    }

    inline std::string AddOptionalEncapulation(const Declaration& optional_declaration)
    {
        auto inner_type = optional_declaration.m_edl_type_info.inner_type;
        auto inner_type_name = EdlTypeToRustType(*inner_type);

        return std::format("Option<{}>", inner_type_name);
    }

    inline std::string GetFullDeclarationType(const Declaration& declaration)
    {
        EdlTypeKind type_kind = declaration.m_edl_type_info.m_type_kind;
        std::string type_name = EdlTypeToRustType(declaration.m_edl_type_info);

        if (type_kind == EdlTypeKind::Void)
        {
            return "()";
        }

        if (declaration.IsEdlType(EdlTypeKind::Optional))
        {
            return AddOptionalEncapulation(declaration);
        }

        if (declaration.IsEdlType(EdlTypeKind::Vector))
        {
            type_name = AddVectorEncapulation(declaration);
        }

        if (!declaration.m_array_dimensions.empty())
        {
            auto arr_size = declaration.m_array_dimensions.front();
            type_name = std::format(c_array_initializer, type_name, TransformCaseToUpper(arr_size));
        }

        return type_name;
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

    inline std::string GetParameterForFunction(const Declaration& declaration)
    {
        std::string full_type = GetFullDeclarationType(declaration);
        std::string param_declarator = GetParameterSyntax(declaration);

        return std::format("{}: {}{}", declaration.m_name, param_declarator, full_type);
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
        std::ostringstream abi_struct_fill_statments {};
        auto tabs = GenerateTabs(indentation);
        for (auto& param : parameters)
        {
            if (param.IsInParameter())
            {
                abi_struct_fill_statments << std::format(
                    "{}abi_type.m_{} = {}.clone();\n",
                    tabs,
                    param.m_name,
                    param.m_name);
            }
        }

        return abi_struct_fill_statments.str();
    }

    inline std::string GetMoveFromAbiStructToParamStatements(
        uint32_t indentation,
        const std::vector<Declaration>& parameters)
    {
        std::ostringstream param_update_statements {};
        auto tabs = GenerateTabs(indentation);
        for (auto& param : parameters)
        {
            if (param.IsInOutOrOutParameter())
            {
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
            abi_struct_fields << std::format("{}abi_type.m_{}", GetParameterSyntax(param), param.m_name);
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
