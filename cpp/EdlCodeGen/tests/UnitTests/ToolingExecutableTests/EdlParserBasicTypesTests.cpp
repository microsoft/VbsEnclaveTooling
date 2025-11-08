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

TEST_CLASS(EdlParserBasicTypesTests)
{
    public:

    // Trusted functions
    TEST_METHOD(Parse_TrustedWithBasicTypes_Function)
    {
        ParseAndValidateTestFunction(m_basic_edl_file_name, "TrustedWithBasicTypes", FunctionKind::Trusted, EdlTypeKind::Void);
    }

    TEST_METHOD(Parse_RetChar_Trusted_Function)
    {
        ParseAndValidateTestFunction(m_basic_edl_file_name, "RetChar", FunctionKind::Trusted, EdlTypeKind::Char);
    }

    TEST_METHOD(Parse_RetWchar_t_Trusted_Function)
    {
        ParseAndValidateTestFunction(m_basic_edl_file_name, "RetWchar_t", FunctionKind::Trusted, EdlTypeKind::WChar);
    }

    TEST_METHOD(Parse_RetFloat_Trusted_Function)
    {
        ParseAndValidateTestFunction(m_basic_edl_file_name, "RetFloat", FunctionKind::Trusted, EdlTypeKind::Float);
    }

    TEST_METHOD(Parse_RetDouble_Trusted_Function)
    {
        ParseAndValidateTestFunction(m_basic_edl_file_name, "RetDouble", FunctionKind::Trusted, EdlTypeKind::Double);
    }

    TEST_METHOD(Parse_RetSize_t_Trusted_Function)
    {
        ParseAndValidateTestFunction(m_basic_edl_file_name, "RetSize_t", FunctionKind::Trusted, EdlTypeKind::SizeT);
    }

    TEST_METHOD(Parse_RetInt8_t_Trusted_Function)
    {
        ParseAndValidateTestFunction(m_basic_edl_file_name, "RetInt8_t", FunctionKind::Trusted, EdlTypeKind::Int8);
    }

    TEST_METHOD(Parse_RetInt16_t_Trusted_Function)
    {
        ParseAndValidateTestFunction(m_basic_edl_file_name, "RetInt16_t", FunctionKind::Trusted, EdlTypeKind::Int16);
    }

    TEST_METHOD(Parse_RetInt32_t_Trusted_Function)
    {
        ParseAndValidateTestFunction(m_basic_edl_file_name, "RetInt32_t", FunctionKind::Trusted, EdlTypeKind::Int32);
    }

    TEST_METHOD(Parse_RetInt64_t_Trusted_Function)
    {
        ParseAndValidateTestFunction(m_basic_edl_file_name, "RetInt64_t", FunctionKind::Trusted, EdlTypeKind::Int64);
    }

    TEST_METHOD(Parse_RetUint8_t_Trusted_Function)
    {
        ParseAndValidateTestFunction(m_basic_edl_file_name, "RetUint8_t", FunctionKind::Trusted, EdlTypeKind::UInt8);
    }

    TEST_METHOD(Parse_RetUint16_t_Trusted_Function)
    {
        ParseAndValidateTestFunction(m_basic_edl_file_name, "RetUint16_t", FunctionKind::Trusted, EdlTypeKind::UInt16);
    }

    TEST_METHOD(Parse_RetUint32_t_Trusted_Function)
    {
        ParseAndValidateTestFunction(m_basic_edl_file_name, "RetUint32_t", FunctionKind::Trusted, EdlTypeKind::UInt32);
    }

    TEST_METHOD(Parse_RetUint64_t_Trusted_Function)
    {
        ParseAndValidateTestFunction(m_basic_edl_file_name, "RetUint64_t", FunctionKind::Trusted, EdlTypeKind::UInt64);
    }

    TEST_METHOD(Parse_RetVoid_Trusted_Function)
    {
        ParseAndValidateTestFunction(m_basic_edl_file_name, "RetVoid", FunctionKind::Trusted, EdlTypeKind::Void);
    }

    TEST_METHOD(Parse_RetUint32Ptr_Trusted_Function)
    {
        ParseAndValidateTestFunction(m_basic_edl_file_name, "RetUint32Ptr", FunctionKind::Trusted, EdlTypeKind::UInt32, FunctionReturnKind::Ptr);
    }

    // Untrusted functions

    TEST_METHOD(Parse_UntrustedWithBasicTypes_Function)
    {
        ParseAndValidateTestFunction(m_basic_edl_file_name, "UntrustedWithBasicTypes", FunctionKind::Untrusted, EdlTypeKind::Void);
    }

    TEST_METHOD(Parse_RetChar_Untrusted_Function)
    {
        ParseAndValidateTestFunction(m_basic_edl_file_name, "RetChar", FunctionKind::Untrusted, EdlTypeKind::Char);
    }

    TEST_METHOD(Parse_RetWchar_t_Untrusted_Function)
    {
        ParseAndValidateTestFunction(m_basic_edl_file_name, "RetWchar_t", FunctionKind::Untrusted, EdlTypeKind::WChar);
    }

    TEST_METHOD(Parse_RetFloat_Untrusted_Function)
    {
        ParseAndValidateTestFunction(m_basic_edl_file_name, "RetFloat", FunctionKind::Untrusted, EdlTypeKind::Float);
    }

    TEST_METHOD(Parse_RetDouble_Untrusted_Function)
    {
        ParseAndValidateTestFunction(m_basic_edl_file_name, "RetDouble", FunctionKind::Untrusted, EdlTypeKind::Double);
    }

    TEST_METHOD(Parse_RetSize_t_Untrusted_Function)
    {
        ParseAndValidateTestFunction(m_basic_edl_file_name, "RetSize_t", FunctionKind::Untrusted, EdlTypeKind::SizeT);
    }

    TEST_METHOD(Parse_RetInt8_t_Untrusted_Function)
    {
        ParseAndValidateTestFunction(m_basic_edl_file_name, "RetInt8_t", FunctionKind::Untrusted, EdlTypeKind::Int8);
    }

    TEST_METHOD(Parse_RetInt16_t_Untrusted_Function)
    {
        ParseAndValidateTestFunction(m_basic_edl_file_name, "RetInt16_t", FunctionKind::Untrusted, EdlTypeKind::Int16);
    }

    TEST_METHOD(Parse_RetInt32_t_Untrusted_Function)
    {
        ParseAndValidateTestFunction(m_basic_edl_file_name, "RetInt32_t", FunctionKind::Untrusted, EdlTypeKind::Int32);
    }

    TEST_METHOD(Parse_RetInt64_t_Untrusted_Function)
    {
        ParseAndValidateTestFunction(m_basic_edl_file_name, "RetInt64_t", FunctionKind::Untrusted, EdlTypeKind::Int64);
    }

    TEST_METHOD(Parse_RetUint8_t_Untrusted_Function)
    {
        ParseAndValidateTestFunction(m_basic_edl_file_name, "RetUint8_t", FunctionKind::Untrusted, EdlTypeKind::UInt8);
    }

    TEST_METHOD(Parse_RetUint16_t_Untrusted_Function)
    {
        ParseAndValidateTestFunction(m_basic_edl_file_name, "RetUint16_t", FunctionKind::Untrusted, EdlTypeKind::UInt16);
    }

    TEST_METHOD(Parse_RetUint32_t_Untrusted_Function)
    {
        ParseAndValidateTestFunction(m_basic_edl_file_name, "RetUint32_t", FunctionKind::Untrusted, EdlTypeKind::UInt32);
    }

    TEST_METHOD(Parse_RetUint64_t_Untrusted_Function)
    {
        ParseAndValidateTestFunction(m_basic_edl_file_name, "RetUint64_t", FunctionKind::Untrusted, EdlTypeKind::UInt64);
    }

    TEST_METHOD(Parse_RetVoid_Untrusted_Function)
    {
        ParseAndValidateTestFunction(m_basic_edl_file_name, "RetVoid", FunctionKind::Untrusted, EdlTypeKind::Void);
    }

    TEST_METHOD(Parse_RetUint32Ptr_Untrusted_Function)
    {
        ParseAndValidateTestFunction(m_basic_edl_file_name, "RetUint32Ptr", FunctionKind::Untrusted, EdlTypeKind::UInt32, FunctionReturnKind::Ptr);
    }
};
}
