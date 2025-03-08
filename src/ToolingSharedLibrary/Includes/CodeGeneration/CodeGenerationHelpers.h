// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once 
#include <pch.h>
#include <Edl\Structures.h>
#include <Edl\Utils.h>
#include <CodeGeneration\Contants.h>
#include <Exceptions.h>
#include <windows.h>
#include <wil\result_macros.h>
#include "Flatbuffers\Contants.h"
using namespace EdlProcessor;
using namespace ToolingExceptions;

namespace CodeGeneration
{
    // For us to distinguish who we expect to call the function.
    // based on this info we will generate the function differently.
    enum class FunctionCallInitiator : std::uint32_t
    {
        Developer,
        Abi,
    };

    enum class CallFlowDirection : std::uint32_t
    {
        HostAppToEnclave,
        EnclaveToHostApp,
    };

    enum class ParameterModifier : std::uint32_t
    {
        NoConst,
        InParameterConst,
    };

    enum class CodeGenStructKind : std::uint32_t
    {
        DeveloperStruct,
        NonDeveloperAbiStruct,
    };

    static std::unordered_set<EdlTypeKind, EdlTypeToHash> const_ref_types
    {
        EdlTypeKind::String,
        EdlTypeKind::WString,
        EdlTypeKind::Struct,
    };

    static std::unordered_set<EdlTypeKind, EdlTypeToHash> s_complex_types
    {
        EdlTypeKind::String,
        EdlTypeKind::WString,
        EdlTypeKind::Struct,
    };

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

            if (attribute.m_in_and_out_present)
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

    static inline std::string GetSizeForCopy(
        const std::optional<ParsedAttributeInfo>& attribute_optional,
        std::string_view parameter_type)
    {
        // Size and count attributes are only for pointers
        if (attribute_optional.has_value() && attribute_optional.value().IsSizeOrCountPresent())
        {
            auto& attribute = attribute_optional.value();
            auto& size_or_count_token = (attribute.m_count_info.IsEmpty()) 
                ? attribute.m_size_info 
                : attribute.m_count_info;

            std::string size_or_count {};

            if (size_or_count_token.IsUnsignedInteger())
            {
                size_or_count = std::format("{}U", size_or_count_token.ToString());
            }
            else
            {
                // This should be a numeric parameter within a function/struct or an enum value.
                size_or_count = std::format("{}", size_or_count_token.ToString());
            }

            if (!attribute.m_count_info.IsEmpty())
            {
                // For count attribute. We see this as copying sizeof(parameter) multiplied
                // by the count value.
                return std::format(c_count_statement, parameter_type, size_or_count);
            }
            else if (!attribute.m_size_info.IsEmpty())
            {
                // For size attribute. We see this as copying the raw value in bytes.
                // e.g [size=50] on a function parameter or struct field for example 
                // tells us to copy 50 bytes of data.
                return size_or_count;
            }
        }

        // No size or count attribute so use sizeof(parameter). 
        // Size/Count are mandatory for pointers to primitives. Without that edl parsing would
        // have failed. So, if we get here, then we're looking at a struct.
        return std::format(c_copy_value_func_size_t_param, parameter_type);
    };

    enum class ParamCopyCase : std::uint32_t
    {
        CallToVtl1FromVtl0_CopyVtl0ParametersIntoVtl1Parameters,
        ReturnFromVtl1ToVtl0_CopyVtl1ParametersToVtl0Parameters,
        CallToVtl0FromVtl1_CopyVtl1ParametersToVtl0Parameters,
        ReturnFromVtl0ToVtl1_CopyVtl0ParametersIntoVtl1Parameters,
    };

    static inline std::string GetCopyStatement(
        Declaration parameter,
        std::string_view param_type,
        std::string_view size_to_copy,
        std::string_view desc_name,
        std::string_view src_name,
        ParamCopyCase copy_case)
    {
        if (parameter.HasPointer())
        {
            auto& attribute = parameter.m_attribute_info.value();
            bool is_in_out = attribute.m_in_and_out_present && attribute.m_out_present;
            bool is_out = attribute.m_out_present;
            bool is_in = !is_in_out && !is_out;

            // The following copy statements are used inside the entry point functions in the HostApp -> enclave call
            // flow. By entry point we mean the initial abi function the developer calls in (vtl0) and the abi function that 
            // calls its vtl1 impl counterpart.

            // Case where we're in a vtl1 function and need to copy the vtl0 parameter to a vtl1 heap to forward it
            // to a vtl1 function. Vtl1 abi func -> Vtl1 developer impl. Original parameters sent by vtl0.
            if ((is_in || is_in_out)
                && copy_case == ParamCopyCase::CallToVtl1FromVtl0_CopyVtl0ParametersIntoVtl1Parameters)
            {
                return std::format(
                    c_copy_param_into_vtl1_heap_from_vtl0,
                    desc_name,
                    src_name,
                    size_to_copy,
                    param_type,
                    parameter.m_name,
                    desc_name);

            }
            else if (is_out && copy_case == ParamCopyCase::CallToVtl1FromVtl0_CopyVtl0ParametersIntoVtl1Parameters)
            {
                return std::format(c_copy_out_param_into_vtl1_heap_from_vtl0,
                    desc_name,
                    parameter.m_name,
                    param_type,
                    parameter.m_name,
                    desc_name);
            }
            // Return case where we're in a vtl1 function and returning in-out/out/return values back to a vtl0 function.
            else if (is_in_out && copy_case == ParamCopyCase::ReturnFromVtl1ToVtl0_CopyVtl1ParametersToVtl0Parameters)
            {
                return std::format(c_copy_vtl1_param_ptr_into_vtl0_no_alloc, desc_name, src_name, size_to_copy);
            }
            else if (is_out && copy_case == ParamCopyCase::ReturnFromVtl1ToVtl0_CopyVtl1ParametersToVtl0Parameters)
            {
                return std::format(
                    c_copy_vtl1_out_param_ptr_into_vtl0_no_alloc,
                    parameter.m_name,
                    src_name,
                    size_to_copy);
            }

            // The following copy statements are for the entry functions in the Enclave -> HostApp call flow.
            // By entry point we mean the initial abi function the developer calls (vtl1) when wanting to invoke
            // their actual impl callback function in vtl0.

            // Case where we're in a vtl1 function and need to copy the vtl1 parameters into the vtl0 heap 
            // then forward them to the vtl0 callback.
            if ((is_in || is_in_out) &&
                (copy_case == ParamCopyCase::CallToVtl0FromVtl1_CopyVtl1ParametersToVtl0Parameters))
            {
                return std::format(
                    c_allocate_vtl0_param_and_copy_vtl1_memory_into_it,
                    desc_name,
                    src_name,
                    size_to_copy,
                    param_type,
                    parameter.m_name,
                    desc_name);
            }
            else if (is_out && copy_case == ParamCopyCase::CallToVtl0FromVtl1_CopyVtl1ParametersToVtl0Parameters)
            {
                return std::format(c_allocate_vtl0_out_param_and_copy_vtl1_memory_into_it,
                    desc_name,
                    param_type,
                    desc_name,
                    param_type,
                    param_type,
                    parameter.m_name,
                    desc_name);
            }

            // Case where we're returning back from a vtl1 function after a vtl0 callback invocation,
            // so we need to copy the return vtl0 memory back into the vtl1 in-out/out/ params.
            if (is_in_out && copy_case == ParamCopyCase::ReturnFromVtl0ToVtl1_CopyVtl0ParametersIntoVtl1Parameters)
            {
                return std::format(c_copy_vtl0_param_into_vtl1_without_allocation, desc_name, src_name, size_to_copy);
            }
            if (is_out && copy_case == ParamCopyCase::ReturnFromVtl0ToVtl1_CopyVtl0ParametersIntoVtl1Parameters)
            {
                return std::format(
                    c_copy_out_param_with_allocation_vtl1,
                    parameter.m_name,
                    src_name,
                    size_to_copy);
            }
        }

        // non pointer value. Note: We don't need to worry about allocating and copying memory for value types inside the
        // generated function. This is because these are copied by default using memcpy in the HostHelpers.h 'CallVtl*"
        // functions or the enclave memory accessors functions implicitly in the EnclaveHelpers.h 'CallVtl*' functions.
        return std::format(c_copy_value_param_function, desc_name, src_name, size_to_copy);
    }

    inline std::string CopyReturnTupleValuesIntoParameters(
        const std::vector<std::pair<std::string, size_t>>& return_tuple_data)
    {
        std::ostringstream copy_statements_for_return_tuple;

        for (auto&& [param_name, index] : return_tuple_data)
        {
            auto get_value_in_tuple = std::format(c_get_return_tuple_value, index);
            copy_statements_for_return_tuple << std::format(
                c_assign_tuple_value_to_parameter,
                param_name,
                get_value_in_tuple);
        }

        return copy_statements_for_return_tuple.str();
    }

    void inline InvokeFlatbufferCompiler(std::string_view compiler_path, std::string_view args)
    {
        PrintStatus(Status::Info, Flatbuffers::c_failed_to_compile_flatbuffer_msg.data());
        std::string complete_argument = std::format("{} {}", compiler_path, args);
        auto result = std::system(complete_argument.c_str());

        if (result)
        {
            throw CodeGenerationException(ErrorId::FlatbufferCompilerError, result);
        }

        PrintStatus(Status::Info, Flatbuffers::c_succeeded_compiling_flatbuffer_msg.data());
    }

    template<typename... Args>
    inline std::string FormatString(std::string_view format_string, Args&&... args)
    {
        return std::vformat(format_string, std::make_format_args(args...));   
    }

    inline bool TypeContainsIterator(const Declaration& declaration)
    {
        if (!declaration.m_array_dimensions.empty())
        {
            return true;
        }

        if (declaration.m_edl_type_info.m_type_kind == EdlTypeKind::Vector ||
            declaration.m_edl_type_info.m_type_kind == EdlTypeKind::String ||
            declaration.m_edl_type_info.m_type_kind == EdlTypeKind::WString)
        {
            return true;
        }

        return false;
    }

    inline std::string GetSimpleTypeInfo(const EdlTypeInfo& info)
    {
        switch (info.m_type_kind)
        {
            case EdlTypeKind::UInt8:
            case EdlTypeKind::UInt16:
            case EdlTypeKind::UInt32:
            case EdlTypeKind::UInt64:
            case EdlTypeKind::Int8:
            case EdlTypeKind::Int16:
            case EdlTypeKind::Int32:
            case EdlTypeKind::Int64:
            case EdlTypeKind::String:
            case EdlTypeKind::WString:
                return std::format("std::{}", info.m_name);
            default:
                return info.m_name;
        }
    }

    enum class PtrKind
    {
        unique,
        shared,
    };

    inline std::string AddUniquePtr(std::string_view type)
    {
        return std::format("{}", type);
    }

    inline std::string EncapsulateInPtrIfStruct(const EdlTypeInfo& type_info, PtrKind = PtrKind::unique)
    {
        if (type_info.m_type_kind == EdlTypeKind::Struct)
        {
            return AddUniquePtr(type_info.m_name);
        }

        return {};
    }

    inline std::string AddVectorEncapulation(const Declaration& vector_declaration)
    {
        auto inner_type = vector_declaration.m_edl_type_info.inner_type;
        auto inner_type_name = GetSimpleTypeInfo(*inner_type);
        auto type_with_unique_ptr = EncapsulateInPtrIfStruct(*inner_type);

        if (!type_with_unique_ptr.empty())
        {
            return std::format("std::vector<{}>", type_with_unique_ptr);
        }
        
        return std::format("std::vector<{}>", inner_type_name);
    }

    inline std::string AddArrayEncapulation(
        std::string type_name,
        const Declaration& array_declaration)
    {
        auto type_with_unique_ptr = EncapsulateInPtrIfStruct(array_declaration.m_edl_type_info);
        const ArrayDimensions& dimensions = array_declaration.m_array_dimensions;
        if (!type_with_unique_ptr.empty())
        {
            return std::format(c_array_initializer, type_with_unique_ptr, dimensions.front());

        }

        return std::format(c_array_initializer, type_name, dimensions.front());
    }

    inline std::string GetFullDeclarationType(const Declaration& declaration)
    {
        EdlTypeKind type_kind = declaration.m_edl_type_info.m_type_kind;
        std::string type_name = GetSimpleTypeInfo(declaration.m_edl_type_info);

        if (declaration.IsEdlType(EdlTypeKind::Vector))
        {
            return AddVectorEncapulation(declaration);
        }

        if (!declaration.m_array_dimensions.empty())
        {
            return AddArrayEncapulation(type_name, declaration);
        }

        return type_name;
    }

    inline std::string GetParameterQualifier(const Declaration& declaration)
    {
        if (declaration.IsInParameterOnly())
        {
            return "const";
        }

        return {};
    }

    inline std::string GetParameterDeclarator(const Declaration& declaration)
    {
        if (c_edlTypes_primitive_set.contains(declaration.m_edl_type_info.m_type_kind))
        {
            return {};
        }

        return "&";
    }

    inline std::string GetParameterForFunction(const Declaration& declaration)
    {
        std::string full_type = GetFullDeclarationType(declaration);
        std::string qualifier = GetParameterQualifier(declaration);
        std::string param_declarator = GetParameterDeclarator(declaration);

        return std::format("{} {}{} {}", qualifier, full_type, param_declarator, declaration.m_name);
    }

    inline std::string GetToDevTypeFunctionName(const Declaration& declaration)
    {
        if (!declaration.IsEdlType(EdlTypeKind::Struct))
        {
            if (declaration.IsEdlType(EdlTypeKind::Vector) &&
                !declaration.IsInnerEdlType(EdlTypeKind::Struct))
            {
                
                throw std::runtime_error("Only pointers to structs currently supported");
            }
        }

        if (declaration.HasPointer())
        {
            return "ToDevType";
        }

        return "ToDevTypeNoPtr";
    }

    inline bool ShouldForwardPointerToDevImpl(const Declaration& declaration)
    {
        bool is_struct = declaration.IsEdlType(EdlTypeKind::Struct);
        
        // Currently only pointer to struct supported.
        if (declaration.HasPointer() && is_struct)
        {
            return true;
        }

        return false;
    }
}
