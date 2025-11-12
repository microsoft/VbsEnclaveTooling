// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once 
#include <pch.h>
#include <CodeGeneration\Common\Helpers.h>
#include <CodeGeneration\Cpp\Constants.h>
#include <CodeGeneration\Flatbuffers\Constants.h>
#include <Edl\Structures.h>
#include <Edl\Utils.h>
#include <Exceptions.h>

using namespace EdlProcessor;
using namespace ToolingExceptions;

namespace CodeGeneration::Cpp
{
    using namespace CodeGeneration::Common;

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

    inline std::string EdlTypeToCppType(const EdlTypeInfo& info)
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
            case EdlTypeKind::UIntPtr:
            case EdlTypeKind::String:
            case EdlTypeKind::WString:
                return std::format("std::{}", info.m_name);
            default:
                return info.m_name;
        }
    }

    enum class PtrKind
    {
        raw,
        unique,
        shared,
    };

    inline std::string AddPtr(std::string_view type, PtrKind ptr_kind)
    {
        switch (ptr_kind)
        {
            case PtrKind::unique:
                return std::format("std::unique_ptr<{}>", type);
            case PtrKind::shared:
                return std::format("std::shared_ptr<{}>", type);
            default:
                return std::format("{}*", type);
        }
    }

    inline std::string EncapsulateInPtr(
        const Declaration& declaration,
        const EdlTypeInfo& type_info)
    {
        bool declaration_for_function = declaration.m_parent_kind == DeclarationParentKind::Function;

        if (declaration_for_function)
        {
            if (declaration.IsOutParameterOnly())
            {
                return AddPtr(type_info.m_name, PtrKind::unique);
            }

            // In and Inout pointers will be raw pointers since the function that will be using them 
            // is non owning.
            return AddPtr(type_info.m_name, PtrKind::raw);
        }

        return AddPtr(type_info.m_name, PtrKind::unique);;
    }

    inline std::string AddVectorEncapulation(const Declaration& vector_declaration)
    {
        auto inner_type = vector_declaration.m_edl_type_info.inner_type;
        auto inner_type_name = EdlTypeToCppType(*inner_type);
        std::string type_with_ptr {};

        if (vector_declaration.HasPointer())
        {
            type_with_ptr = EncapsulateInPtr(vector_declaration, *inner_type);
        }

        if (!type_with_ptr.empty())
        {
            return std::format("std::vector<{}>", type_with_ptr);
        }

        return std::format("std::vector<{}>", inner_type_name);
    }

    inline std::string AddArrayEncapulation(
        std::string type_name,
        const Declaration& array_declaration)
    {
        const ArrayDimensions& dimensions = array_declaration.m_array_dimensions;
        std::string type_with_ptr {};

        if (array_declaration.HasPointer())
        {
            type_with_ptr = EncapsulateInPtr(array_declaration, array_declaration.m_edl_type_info);
        }

        if (!type_with_ptr.empty())
        {
            return std::format(c_array_initializer, type_with_ptr, dimensions.front());
        }

        return std::format(c_array_initializer, type_name, dimensions.front());
    }

    inline std::string AddOptionalEncapulation(const Declaration& optional_declaration)
    {
        auto inner_type = optional_declaration.m_edl_type_info.inner_type;
        auto inner_type_name = EdlTypeToCppType(*inner_type);

        return std::format("std::optional<{}>", inner_type_name);
    }

    inline std::string GetFullDeclarationType(const Declaration& declaration)
    {
        EdlTypeKind type_kind = declaration.m_edl_type_info.m_type_kind;
        std::string type_name = EdlTypeToCppType(declaration.m_edl_type_info);

        if (declaration.IsEdlType(EdlTypeKind::Vector))
        {
            return AddVectorEncapulation(declaration);
        }

        if (!declaration.m_array_dimensions.empty())
        {
            return AddArrayEncapulation(type_name, declaration);
        }

        if (declaration.IsEdlType(EdlTypeKind::Optional))
        {
            return AddOptionalEncapulation(declaration);
        }

        if (declaration.HasPointer())
        {
            auto type_with_ptr = EncapsulateInPtr(declaration, declaration.m_edl_type_info);
            
            if (!type_with_ptr.empty())
            {
                return type_with_ptr;
            }
        }
        
        return type_name;
    }

    inline std::string GetParameterQualifier(const Declaration& declaration)
    {
        // only non primitive in parameters should contain const qualifier
        if (declaration.IsInParameterOnly())
        {
            if (declaration.HasPointer() || !declaration.IsPrimitiveType())
            {
                return "const";
            }
        }

        return {};
    }

    inline std::string GetParameterDeclarator(const Declaration& declaration)
    {
        // In and InOut pointers will only ever be raw pointers. While out parameters
        // will be shared pointers, in which case we pass a reference to the developers
        // impl function.
        if (declaration.HasPointer() && !declaration.IsOutParameterOnly())
        {
            return {};
        }
        
        // Primitive In parameters should not have a reference declarator.
        if (declaration.IsInParameterOnly() && declaration.IsPrimitiveType())
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
    
    inline bool ShouldFieldInReturnedStructBeMoved(
        const Declaration& declaration,
        const OrderedMap<std::string, DeveloperType>& developer_types)
    {
        if (declaration.IsPrimitiveType())
        {
            return false;
        }

        if (declaration.IsContainerType())
        {
            return true;
        }
        
        // Only type left should be a struct. If the struct or any of the types in its fields 
        // contain a pointer or is a container type, then the struct should be moved.
        auto& dev_type = developer_types.at(declaration.m_edl_type_info.m_name);

        return dev_type.m_contains_inner_pointer || dev_type.m_contains_container_type;
    }
}
