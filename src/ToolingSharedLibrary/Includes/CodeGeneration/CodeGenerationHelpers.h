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
    enum class CodeGenFunctionKind : std::uint32_t
    {
        Developer,
        Abi,
    };

    enum class FunctionDirection : std::uint32_t
    {
        HostAppToEnclave,
        EnclaveToHostApp,
    };

    enum class ParamModifier : std::uint32_t
    {
        ConstReference,
        Reference,
        ConstOnly,
        NoConstNoReference
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
        const ParsedAttributeInfo& attribute,
        std::string_view parameter_name,
        std::string_view parameter_type)
    {
        // Size and count attributes are only for pointers
        if (attribute.IsSizeOrCountPresent())
        {
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

            // For size attribute. We see this as copying the raw value in bytes.
            // e.g [size=50] on a function parameter or struct field for example 
            // tells us to copy 50 bytes of data.
            return size_or_count;
        }

        // No size or count attribute so use sizeof(parameter). 
        // Size/Count are mandatory for pointers to primitives. Without that edl parsing would
        // have failed. So, if we get here, then we're looking at a struct.
        return std::format(c_copy_value_func_size_t_param, parameter_type);
    };

    enum class ParamCopyDirection : std::uint32_t
    {
        ForReturnCase_InsideVtl0CopyVtl0HeapParamToVariable,
        ForReturnCase_InsideVtl1CopyVtl1ParamToVtl0Heap,
        ForReturnCase_InsideVtl1CopyVtl0HeapParamToVariable,
        ForReturnCase_InsideVtl0CopyVtl0ParamToVtl0Heap,
        ForForwardingCase_InsideVtl1CopyVtl1ParamToVtl0Heap,
    };

    static inline std::string GetCopyStatement(
        bool has_pointer, 
        const ParsedAttributeInfo& attribute,
        std::string_view param_type,
        std::string_view assignee,
        std::string_view value_to_assign,
        ParamCopyDirection direction)
    {
        auto size = GetSizeForCopy(attribute, value_to_assign, param_type);
        bool is_in_out = attribute.m_in_and_out_present && attribute.m_out_present;
        bool is_out = attribute.m_out_present;
        if (has_pointer)
        {
            std::ostringstream copy_with_deallocation_str{};

            // The following create copy statements are used inside the entry point functions in the HostApp -> enclave call
            // flow. By entry point we mean the initial abi function the developer calls in (vtl0) and the abi function that 
            // calls its vtl1 impl counterpart.
            if (is_in_out && direction == ParamCopyDirection::ForReturnCase_InsideVtl0CopyVtl0HeapParamToVariable)
            {
                // Developer must deallocate.
                return std::format(c_copy_in_out_param_without_allocation, assignee, value_to_assign, size);
            }
            else if (is_out && direction == ParamCopyDirection::ForReturnCase_InsideVtl0CopyVtl0HeapParamToVariable)
            {
                // Developer must deallocate.
                return std::format(c_copy_out_param_without_allocation, assignee, value_to_assign, size);
            }
            else if (is_in_out && direction == ParamCopyDirection::ForReturnCase_InsideVtl1CopyVtl1ParamToVtl0Heap)
            {
                // No deallocation needed, developer on vtl0 side must deallocate.
                return std::format(c_copy_in_out_param_into_vtl0_heap, assignee, value_to_assign, size);
            }
            else if (is_out && direction == ParamCopyDirection::ForReturnCase_InsideVtl1CopyVtl1ParamToVtl0Heap)
            {
                // No deallocation needed, developer on vtl0 side must deallocate.
                return std::format(c_copy_out_param_into_vtl0_heap_from_vtl1, assignee, value_to_assign, size);
            }

            // The following create copy statements for the entry function functions in the Enclave -> HostApp call flow.
            // By entry point we mean the initial abi function the developer calls (vtl1) and their actual impl callback function (vtl0).
            if (is_in_out && direction == ParamCopyDirection::ForReturnCase_InsideVtl1CopyVtl0HeapParamToVariable)
            {
                // copy the vtl0 memory to vtl1 and then deallocate it. Developer must free vtl1 allocated memory.
                copy_with_deallocation_str << std::format(c_copy_in_out_param_without_allocation, assignee, value_to_assign, size);
                copy_with_deallocation_str << std::format(c_deallocate_vtl0_in_out_mem_from_vtl1, value_to_assign);
                return copy_with_deallocation_str.str();
            }
            else if (is_out && direction == ParamCopyDirection::ForReturnCase_InsideVtl1CopyVtl0HeapParamToVariable)
            {
                // copy the vtl0 memory to vtl1 and then deallocate it. Developer must free vtl1 allocated memory.
                copy_with_deallocation_str << std::format(c_copy_out_param_without_allocation, assignee, value_to_assign, size);
                copy_with_deallocation_str << std::format(c_deallocate_vtl0_out_mem_from_vtl1, value_to_assign);
                return copy_with_deallocation_str.str();
            }
            else if (is_in_out && direction == ParamCopyDirection::ForReturnCase_InsideVtl0CopyVtl0ParamToVtl0Heap)
            {
                // Vtl1 side will deallocate
                return std::format(c_copy_in_out_param_into_vtl0_heap, assignee, value_to_assign, size);
            }
            else if (is_out && direction == ParamCopyDirection::ForReturnCase_InsideVtl0CopyVtl0ParamToVtl0Heap)
            {
                // Vtl1 side will deallocate
                return std::format(c_copy_out_param_into_vtl0_heap, assignee, value_to_assign, size);
            }

            // case where this is vtl1 and the in param has a pointer.
            if (direction == ParamCopyDirection::ForForwardingCase_InsideVtl1CopyVtl1ParamToVtl0Heap)
            {
                // No deallocation needed, developer on vtl0 side must deallocate. But in the future
                // we could add smart pointers to the developer function impl to allow fow lifetime managment.
                return std::format(
                    c_copy_in_param_into_vtl0_heap_from_vtl1, 
                    assignee,
                    value_to_assign,
                    size);
            }
        }

        // non pointer value.
        return std::format(c_copy_value_param_function, assignee, value_to_assign, size);
    }
}
