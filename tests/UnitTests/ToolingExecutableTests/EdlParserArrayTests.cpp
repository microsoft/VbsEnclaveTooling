// Copyright(c) Microsoft Corporation.
// Licensed under the MIT License.

#include <pch.h>
#include "CppUnitTest.h"
#include <CmdlineParsingHelpers.h>
#include <Edl\Parser.h>
#include <Edl\Utils.h>
#include <unordered_set>
#include <Exceptions.h>
#include "EdlParserTestHelpers.h"

using namespace ErrorHelpers;
using namespace ToolingExceptions;
using namespace EdlProcessor;
using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace VbsEnclaveToolingTests
{

TEST_CLASS(EdlParserArrayTests)
{
    public:

    // Trusted functions
    TEST_METHOD(Parse_ArrayChar_Trusted_Function)
    {
        ParseAndValidateTestFunction(m_array_edl_file_name, "ArrayChar", FunctionKind::Trusted, EdlTypeKind::Void);
    }

    TEST_METHOD(Parse_ArrayFloat_Trusted_Function)
    {
        ParseAndValidateTestFunction(m_array_edl_file_name, "ArrayFloat", FunctionKind::Trusted, EdlTypeKind::Void);
    }

    TEST_METHOD(Parse_ArrayDouble_Trusted_Function)
    {
        ParseAndValidateTestFunction(m_array_edl_file_name, "ArrayDouble", FunctionKind::Trusted, EdlTypeKind::Void);
    }

    TEST_METHOD(Parse_ArraySize_t_Trusted_Function)
    {
        ParseAndValidateTestFunction(m_array_edl_file_name, "ArraySize_t", FunctionKind::Trusted, EdlTypeKind::Void);
    }

    TEST_METHOD(Parse_ArrayInt8_t_Trusted_Function)
    {
        ParseAndValidateTestFunction(m_array_edl_file_name, "ArrayInt8_t", FunctionKind::Trusted, EdlTypeKind::Void);
    }

    TEST_METHOD(Parse_ArrayInt16_t_Trusted_Function)
    {
        ParseAndValidateTestFunction(m_array_edl_file_name, "ArrayInt16_t", FunctionKind::Trusted, EdlTypeKind::Void);
    }

    TEST_METHOD(Parse_ArrayInt32_t_Trusted_Function)
    {
        ParseAndValidateTestFunction(m_array_edl_file_name, "ArrayInt32_t", FunctionKind::Trusted, EdlTypeKind::Void);
    }

    TEST_METHOD(Parse_ArrayInt64_t_Trusted_Function)
    {
        ParseAndValidateTestFunction(m_array_edl_file_name, "ArrayInt64_t", FunctionKind::Trusted, EdlTypeKind::Void);
    }

    TEST_METHOD(Parse_ArrayUint8_t_Trusted_Function)
    {
        ParseAndValidateTestFunction(m_array_edl_file_name, "ArrayUint8_t", FunctionKind::Trusted, EdlTypeKind::Void);
    }

    TEST_METHOD(Parse_ArrayUint16_t_Trusted_Function)
    {
        ParseAndValidateTestFunction(m_array_edl_file_name, "ArrayUint16_t", FunctionKind::Trusted, EdlTypeKind::Void);
    }

    TEST_METHOD(Parse_ArrayUint32_t_Trusted_Function)
    {
        ParseAndValidateTestFunction(m_array_edl_file_name, "ArrayUint32_t", FunctionKind::Trusted, EdlTypeKind::Void);
    }

    TEST_METHOD(Parse_ArrayUint64_t_Trusted_Function)
    {
        ParseAndValidateTestFunction(m_array_edl_file_name, "ArrayUint64_t", FunctionKind::Trusted, EdlTypeKind::Void);
    }

    // Untrusted functions

    TEST_METHOD(Parse_ArrayChar_Untrusted_Function)
    {
        ParseAndValidateTestFunction(m_array_edl_file_name, "ArrayChar", FunctionKind::Untrusted, EdlTypeKind::Void);
    }

    TEST_METHOD(Parse_ArrayFloat_Untrusted_Function)
    {
        ParseAndValidateTestFunction(m_array_edl_file_name, "ArrayFloat", FunctionKind::Untrusted, EdlTypeKind::Void);
    }

    TEST_METHOD(Parse_ArrayDouble_Untrusted_Function)
    {
        ParseAndValidateTestFunction(m_array_edl_file_name, "ArrayDouble", FunctionKind::Untrusted, EdlTypeKind::Void);
    }

    TEST_METHOD(Parse_ArraySize_t_Untrusted_Function)
    {
        ParseAndValidateTestFunction(m_array_edl_file_name, "ArraySize_t", FunctionKind::Untrusted, EdlTypeKind::Void);
    }

    TEST_METHOD(Parse_ArrayInt8_t_Untrusted_Function)
    {
        ParseAndValidateTestFunction(m_array_edl_file_name, "ArrayInt8_t", FunctionKind::Untrusted, EdlTypeKind::Void);
    }

    TEST_METHOD(Parse_ArrayInt16_t_Untrusted_Function)
    {
        ParseAndValidateTestFunction(m_array_edl_file_name, "ArrayInt16_t", FunctionKind::Untrusted, EdlTypeKind::Void);
    }

    TEST_METHOD(Parse_ArrayInt32_t_Untrusted_Function)
    {
        ParseAndValidateTestFunction(m_array_edl_file_name, "ArrayInt32_t", FunctionKind::Untrusted, EdlTypeKind::Void);
    }

    TEST_METHOD(Parse_ArrayInt64_t_Untrusted_Function)
    {
        ParseAndValidateTestFunction(m_array_edl_file_name, "ArrayInt64_t", FunctionKind::Untrusted, EdlTypeKind::Void);
    }

    TEST_METHOD(Parse_ArrayUint8_t_Untrusted_Function)
    {
        ParseAndValidateTestFunction(m_array_edl_file_name, "ArrayUint8_t", FunctionKind::Untrusted, EdlTypeKind::Void);
    }

    TEST_METHOD(Parse_ArrayUint16_t_Untrusted_Function)
    {
        ParseAndValidateTestFunction(m_array_edl_file_name, "ArrayUint16_t", FunctionKind::Untrusted, EdlTypeKind::Void);
    }

    TEST_METHOD(Parse_ArrayUint32_t_Untrusted_Function)
    {
        ParseAndValidateTestFunction(m_array_edl_file_name, "ArrayUint32_t", FunctionKind::Untrusted, EdlTypeKind::Void);
    }

    TEST_METHOD(Parse_ArrayUint64_t_Untrusted_Function)
    {
        ParseAndValidateTestFunction(m_array_edl_file_name, "ArrayUint64_t", FunctionKind::Untrusted, EdlTypeKind::Void);
    }
};
}
