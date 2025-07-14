// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once
#include <pch.h>
#include <winerror.h>

namespace ErrorHelpers
{
    static const std::string s_warning_prefix = "Warning: ";
    static const std::string s_info_prefix = "Info: ";
    static const std::string s_error_prefix = "Error: ";

    enum class Status
    {
        Info,
        Warning,
        Error,
    };

    enum class ErrorId : std::uint32_t
    {
        Success = 0,
        LanguageNoMoreArgs,
        UnsupportedLanguage,
        EdlNoMoreArgs,
        EdlDoesNotExist,
        NotAnEdlFile,
        OutputDirNoMoreArgs,
        ErrorHandlingNoMoreArgs,
        ErrorHandlingInvalidType,
        InvalidArgument,
        IncorrectNonHelpArgsProvided,
        MissingArgument,
        EdlCommentEndingNotFound,
        EdlStringEndingNotFound,
        EdlUnexpectedToken,
        EdlFailureToLoadFile,
        EdlExpectedTokenNotFound,
        EdlDuplicateTypeDefinition,
        EdlDuplicateFunctionDeclaration,
        EdlEnumNameIdentifierNotFound,
        EdlEnumValueIdentifierNotFound,
        EdlEnumValueNotFound,
        EdlStructIdentifierNotFound,
        EdlFunctionIdentifierNotFound,
        EdlDeclarationIdentifierMissing,
        EdlIdentifierNameNotFound,
        EdlInvalidAttribute,
        EdlNonSizeOrCountAttributeInStruct,
        EdlDuplicateAttributeFound,
        EdlSizeOrCountAttributeValueMissing,
        EdlPointerToPointerInvalid,
        EdlDeveloperTypesMustBeDefinedBeforeUse,
        EdlTypenameInvalid,
        EdlArrayDimensionIdentifierInvalid,
        EdlOnlySingleDimensionsSupported,
        EdlPointerToVoidMustBeAnnotated,
        EdlPointerMustBeAnnotatedWithDirection,
        EdlPointerToArrayNotAllowed,
        EdlSizeOrCountAttributeNotFound,
        EdlSizeOrCountForArrayNotValid,
        EdlSizeOrCountInvalidType,
        EdlDeveloperTypeNotDefined,
        EdlSizeOrCountValueInvalid,
        EdlTypeNameIdentifierIsReserved,
        EdlEnumNameDuplicated,
        EdlDuplicateFieldOrParameter,
        EdlSizeAndCountNotValidForNonPointer,
        EdlReturnValuesCannotBePointers,
        CodeGenUnableToOpenOutputFile,
        CodeGenUnableToCreateHeaderFile,
        VirtualTrustLayerNoMoreArgs,
        VirtualTrustLayerInvalidType,
        GeneralFailure,
        FlatbufferCompilerNoMoreArgs,
        FlatbufferCompilerDoesNotExist,
        FlatbufferCompilerError,
        FlatbufferTypeNotCompatibleWithEdlType,
        NotAFile,
        EdlVectorMustHaveAValidType,
        EdlVectorNameIdentifierNotFound,
        EdlVectorDoesNotStartWithArrowBracket,
        EdlTypeInVectorMustBePreviouslyDefined,
        EdlNamespaceIdentifierNotFound,
        EdlNamespaceDuplication,
    };

    struct ErrorIdHash
    {
        std::size_t operator()(ErrorId e) const
        {
            return std::hash<std::uint32_t>()(static_cast<std::uint32_t>(e));
        }
    };

    static const std::unordered_map<ErrorId, std::string, ErrorIdHash> c_error_messages =
    {
        // Command line parsing errors
        { ErrorId::LanguageNoMoreArgs,"Unable to find codegen language of choice. No more commandline arguments available to find supported language." },
        { ErrorId::UnsupportedLanguage,"Language '{}' is not supported." },
        { ErrorId::EdlNoMoreArgs,"Unable to find edl file path. No more commandline arguments available to find edl path." },
        { ErrorId::EdlDoesNotExist,"The path to the provided .edl file '{}' does not exist." },
        { ErrorId::NotAnEdlFile,"The path '{}' must be a path to a .edl file." },
        { ErrorId::OutputDirNoMoreArgs,"Unable to find output directory. No more commandline arguments available to find output directory." },
        { ErrorId::ErrorHandlingNoMoreArgs,"Unable to find error handling argument. No more commandline arguments available." },
        { ErrorId::ErrorHandlingInvalidType,"Error handling type '{}' invalid." },
        { ErrorId::InvalidArgument,"Unknown argument: {}" },
        { ErrorId::IncorrectNonHelpArgsProvided,"edlcodegen.exe expects at least '{}' arguments. found: '{}'" },
        { ErrorId::MissingArgument,"Missing arguments. Use '-h' for usage." },
        { ErrorId::VirtualTrustLayerNoMoreArgs, "Unable to find virtual trust layer argument. No more commandline arguments available." },
        { ErrorId::VirtualTrustLayerInvalidType, "Virtual trust layer type invalid. Only 'Enclave' and 'HostApp' can be used." },
        { ErrorId::FlatbufferCompilerNoMoreArgs,"Unable to find flatbuffers compiler file path. No more commandline arguments available to find the path to the flatbuffer compiler file." },
        { ErrorId::FlatbufferCompilerDoesNotExist,"The path to the provided flatbuffer compiler file '{}' does not exist." },
        { ErrorId::NotAFile, "The path '{}' must be to a valid file." },

        // Edl file lexical analysis errors
        { ErrorId::EdlCommentEndingNotFound, "EOF while looking for '*/' to match the '/*'" },
        { ErrorId::EdlStringEndingNotFound, "Could not find ending '\"' for string" },
        { ErrorId::EdlUnexpectedToken, "Unexpected token starting with '{}'" },
        { ErrorId::EdlFailureToLoadFile, "Unable to load '{}'" },

        // Edl parser errors
        { ErrorId::EdlExpectedTokenNotFound, "Expected '{}' but got '{}'" },
        { ErrorId::EdlDuplicateTypeDefinition, "Duplicate definition detected for {}" },
        { ErrorId::EdlDuplicateFunctionDeclaration, "Duplicate function declaration detected for '{}'" },
        { ErrorId::EdlEnumValueIdentifierNotFound, "Expected an identifier for the enum value, but found '{}'. Anonymous enums are not supported." },
        { ErrorId::EdlEnumValueNotFound, "Expected a number for the enum value but found '{}'" },
        { ErrorId::EdlEnumNameIdentifierNotFound, "Expected an identifier name for a enum but found '{}'" },
        { ErrorId::EdlStructIdentifierNotFound, "Expected an identifier name for a struct but found '{}'" },
        { ErrorId::EdlFunctionIdentifierNotFound, "Expected an identifier name for a function but found {}" },
        { ErrorId::EdlIdentifierNameNotFound, "Expected an identifier name but found '{}'" },
        { ErrorId::EdlInvalidAttribute, "the '{}' attribute is not supported." },
        { ErrorId::EdlNonSizeOrCountAttributeInStruct, "Only the 'size' and 'count' attributes are allowed in structs." },
        { ErrorId::EdlDuplicateAttributeFound, "Duplicate '{}' attributes for a struct declaration or a function parameter are not allowed." },
        { ErrorId::EdlSizeOrCountAttributeValueMissing, "the {} attribute is not supported." },
        { ErrorId::EdlPointerToPointerInvalid, "VbsEnclaveTooling .edl files do not support pointer to pointer declarations." },
        { ErrorId::EdlTypenameInvalid, "Reached end of file and no definition was found for type '{}'." },
        { ErrorId::EdlArrayDimensionIdentifierInvalid, "'{}' not supported within array brackets. Arrays in VbsEnclaveTooling .edl files only support arrays with an integer literal '[5]' and arrays with string literals previously declared in the edl file e.g. '[int_max]'." },
        { ErrorId::EdlPointerMustBeAnnotatedWithDirection, "Pointers must have a pointer direction. Use the 'in' or 'out' attribute." },
        { ErrorId::EdlPointerToArrayNotAllowed, "VbsEnclaveTooling .edl files do not support the pointers to arrays or vectors." },
        { ErrorId::EdlSizeOrCountAttributeNotFound, "Could not find '{}' size/count declaration in '{}'." },
        { ErrorId::EdlSizeOrCountForArrayNotValid, "Found size/count attributes for an array in '{}'. This is not supported, only unsigned types are supported." },
        { ErrorId::EdlSizeOrCountInvalidType, "size/count attributes not supported for the '{}' type, found in '{}'. Only unsigned types are supported." },
        { ErrorId::EdlDeveloperTypeNotDefined, "Could not find definition for '{}'." },
        { ErrorId::EdlSizeOrCountValueInvalid, "'{}' is invalid for use with the size/count attributes. The value must be an integer literal or a variable name identifier in the same function/struct scope as the attribute." },
        { ErrorId::EdlTypeNameIdentifierIsReserved, "'{}' is a reserved keyword. You can not use it as a type identifier name." },
        { ErrorId::EdlEnumNameDuplicated, "'{}' enum value already defined." },
        { ErrorId::EdlDuplicateFieldOrParameter, "duplicate name '{}' found in '{}'." },
        { ErrorId::EdlSizeAndCountNotValidForNonPointer, "Size/count attributes are only valid for pointer types. Found type '{}'" },
        { ErrorId::EdlReturnValuesCannotBePointers, "Functions cannot return a pointer. Instead return a struct that contains the pointer and the size of the data it points to." },
        { ErrorId::EdlPointerToVoidMustBeAnnotated, "Pointers to void are not allowed. To use a pointer that does not have a type use the 'uintptr_t' type. Note: The codegen layer will only copy the 'uintptr_t' type, not the data it points to." },
        { ErrorId::EdlOnlySingleDimensionsSupported, "Only linear arrays and vectors are supported." },
        { ErrorId::EdlDeveloperTypesMustBeDefinedBeforeUse, "Developer types must be defined before using. Found '{}'" },
        { ErrorId::EdlVectorMustHaveAValidType, "Vector must contain a valid type." },
        { ErrorId::EdlVectorNameIdentifierNotFound, "Expected an identifier name for a vector but found '{}'" },
        { ErrorId::EdlTypeInVectorMustBePreviouslyDefined, "Types in vectors must be previously defined. Found '{}'" },
        { ErrorId::EdlVectorDoesNotStartWithArrowBracket, "Vectors must be declared with <T>. where T is a valid type" },
        { ErrorId::EdlNamespaceIdentifierNotFound, "Expected an identifier name for a namespace but found '{}'" },
        { ErrorId::EdlNamespaceDuplication, "A namespace has already been defined for the edl file." },

        // CodeGen errors
        { ErrorId::CodeGenUnableToOpenOutputFile, "Failed to open '{}' for writing." },
        { ErrorId::CodeGenUnableToCreateHeaderFile, "Failed to create '{}'." },

        // General
        { ErrorId::GeneralFailure, "edlcodegen.exe returned the following HRESULT: {}." },

        // Flatbuffer errors
        { ErrorId::FlatbufferCompilerError, "Flatbuffer schema failed to compile with error code: {}" }, // The compiler outputs the error message to the cmdline so we just print the error code it exits with.
        { ErrorId::FlatbufferTypeNotCompatibleWithEdlType, "Edl type '{}' found for '{}' not compatible with flatbuffers" },
    };

    template<typename... Args>
    static std::string inline GetErrorMessageById(ErrorId id, Args&&... args)
    {
        // format the error and its arguments
        auto& message = c_error_messages.at(id);
        return std::vformat(message, std::make_format_args(args...));
    }

    static void inline PrintStatus(const Status& status, const std::string& message)
    {
        if (status == Status::Info)
        {
            std::cout << s_info_prefix + message << std::endl;
        }
        else if (status == Status::Warning)
        {
            std::cout << s_warning_prefix + message << std::endl;
        }
        else
        {
            std::cerr << s_error_prefix + message << std::endl;
        }
    }

    template<typename... Args>
    static void inline PrintError(ErrorId id, Args&&... args)
    {
        if (!(c_error_messages.contains(id)))
        {
            std::cerr << "Invalid error ID: " << static_cast<uint32_t>(id) << std::endl;
            return;
        }

        // format the error and its arguments
        PrintStatus(Status::Error, GetErrorMessageById(id, std::forward<Args>(args)...));
    }

    static void inline PrintError(std::string_view error_message)
    {
        PrintStatus(Status::Error, error_message.data());
    }

    static void inline PrintHresult(ErrorId id, HRESULT hr)
    {
        std::stringstream string_stream;
        string_stream << "0x" << std::hex << hr;
        PrintError(ErrorId::GeneralFailure, string_stream.str());
    }
}
