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

TEST_CLASS(EdlParserOptionalTypesTests)
{
    public:

    // Trusted functions
    TEST_METHOD(Parse_TrustedWithOptionalTypes_Function)
    {
        ParseAndValidateTestFunction(c_optional_edl_file_name, "TrustedWithOptionalTypes", FunctionKind::Trusted, EdlTypeKind::Void);
    }

    TEST_METHOD(Parse_RetOptionalChar_Trusted_Function)
    {
        ParseAndValidateTestFunction(c_optional_edl_file_name, "RetOptionalChar", FunctionKind::Trusted, EdlTypeKind::Optional);
    }

    TEST_METHOD(Parse_RetOptionalWchar_t_Trusted_Function)
    {
        ParseAndValidateTestFunction(c_optional_edl_file_name, "RetOptionalWchar_t", FunctionKind::Trusted, EdlTypeKind::Optional);
    }

    TEST_METHOD(Parse_RetOptionalFloat_Trusted_Function)
    {
        ParseAndValidateTestFunction(c_optional_edl_file_name, "RetOptionalFloat", FunctionKind::Trusted, EdlTypeKind::Optional);
    }

    TEST_METHOD(Parse_RetOptionalDouble_Trusted_Function)
    {
        ParseAndValidateTestFunction(c_optional_edl_file_name, "RetOptionalDouble", FunctionKind::Trusted, EdlTypeKind::Optional);
    }

    TEST_METHOD(Parse_RetOptionalSize_t_Trusted_Function)
    {
        ParseAndValidateTestFunction(c_optional_edl_file_name, "RetOptionalSize_t", FunctionKind::Trusted, EdlTypeKind::Optional);
    }

    TEST_METHOD(Parse_RetOptionalInt8_t_Trusted_Function)
    {
        ParseAndValidateTestFunction(c_optional_edl_file_name, "RetOptionalInt8_t", FunctionKind::Trusted, EdlTypeKind::Optional);
    }

    TEST_METHOD(Parse_RetOptionalInt16_t_Trusted_Function)
    {
        ParseAndValidateTestFunction(c_optional_edl_file_name, "RetOptionalInt16_t", FunctionKind::Trusted, EdlTypeKind::Optional);
    }

    TEST_METHOD(Parse_RetOptionalInt32_t_Trusted_Function)
    {
        ParseAndValidateTestFunction(c_optional_edl_file_name, "RetOptionalInt32_t", FunctionKind::Trusted, EdlTypeKind::Optional);
    }

    TEST_METHOD(Parse_RetOptionalInt64_t_Trusted_Function)
    {
        ParseAndValidateTestFunction(c_optional_edl_file_name, "RetOptionalInt64_t", FunctionKind::Trusted, EdlTypeKind::Optional);
    }

    TEST_METHOD(Parse_RetOptionalUint8_t_Trusted_Function)
    {
        ParseAndValidateTestFunction(c_optional_edl_file_name, "RetOptionalUint8_t", FunctionKind::Trusted, EdlTypeKind::Optional);
    }

    TEST_METHOD(Parse_RetOptionalUint16_t_Trusted_Function)
    {
        ParseAndValidateTestFunction(c_optional_edl_file_name, "RetOptionalUint16_t", FunctionKind::Trusted, EdlTypeKind::Optional);
    }

    TEST_METHOD(Parse_RetOptionalUint32_t_Trusted_Function)
    {
        ParseAndValidateTestFunction(c_optional_edl_file_name, "RetOptionalUint32_t", FunctionKind::Trusted, EdlTypeKind::Optional);
    }

    TEST_METHOD(Parse_RetOptionalUint64_t_Trusted_Function)
    {
        ParseAndValidateTestFunction(c_optional_edl_file_name, "RetOptionalUint64_t", FunctionKind::Trusted, EdlTypeKind::Optional);
    }

    TEST_METHOD(Parse_RetOptionalMyStruct_Trusted_Function)
    {
        ParseAndValidateTestFunction(c_optional_edl_file_name, "RetOptionalMyStruct", FunctionKind::Trusted, EdlTypeKind::Optional);
    }

    TEST_METHOD(Parse_RetOptionalMyEnum_Trusted_Function)
    {
        ParseAndValidateTestFunction(c_optional_edl_file_name, "RetOptionalMyEnum", FunctionKind::Trusted, EdlTypeKind::Optional);
    }

    // Untrusted functions

    TEST_METHOD(Parse_UntrustedWithOptionalTypes_Function)
    {
        ParseAndValidateTestFunction(c_optional_edl_file_name, "UntrustedWithOptionalTypes", FunctionKind::Untrusted, EdlTypeKind::Void);
    }

    TEST_METHOD(Parse_RetOptionalChar_Untrusted_Function)
    {
        ParseAndValidateTestFunction(c_optional_edl_file_name, "RetOptionalChar", FunctionKind::Untrusted, EdlTypeKind::Optional);
    }

    TEST_METHOD(Parse_RetOptionalWchar_t_Untrusted_Function)
    {
        ParseAndValidateTestFunction(c_optional_edl_file_name, "RetOptionalWchar_t", FunctionKind::Untrusted, EdlTypeKind::Optional);
    }

    TEST_METHOD(Parse_RetOptionalFloat_Untrusted_Function)
    {
        ParseAndValidateTestFunction(c_optional_edl_file_name, "RetOptionalFloat", FunctionKind::Untrusted, EdlTypeKind::Optional);
    }

    TEST_METHOD(Parse_RetOptionalDouble_Untrusted_Function)
    {
        ParseAndValidateTestFunction(c_optional_edl_file_name, "RetOptionalDouble", FunctionKind::Untrusted, EdlTypeKind::Optional);
    }

    TEST_METHOD(Parse_RetOptionalSize_t_Untrusted_Function)
    {
        ParseAndValidateTestFunction(c_optional_edl_file_name, "RetOptionalSize_t", FunctionKind::Untrusted, EdlTypeKind::Optional);
    }

    TEST_METHOD(Parse_RetOptionalInt8_t_Untrusted_Function)
    {
        ParseAndValidateTestFunction(c_optional_edl_file_name, "RetOptionalInt8_t", FunctionKind::Untrusted, EdlTypeKind::Optional);
    }

    TEST_METHOD(Parse_RetOptionalInt16_t_Untrusted_Function)
    {
        ParseAndValidateTestFunction(c_optional_edl_file_name, "RetOptionalInt16_t", FunctionKind::Untrusted, EdlTypeKind::Optional);
    }

    TEST_METHOD(Parse_RetOptionalInt32_t_Untrusted_Function)
    {
        ParseAndValidateTestFunction(c_optional_edl_file_name, "RetOptionalInt32_t", FunctionKind::Untrusted, EdlTypeKind::Optional);
    }

    TEST_METHOD(Parse_RetOptionalInt64_t_Untrusted_Function)
    {
        ParseAndValidateTestFunction(c_optional_edl_file_name, "RetOptionalInt64_t", FunctionKind::Untrusted, EdlTypeKind::Optional);
    }

    TEST_METHOD(Parse_RetOptionalUint8_t_Untrusted_Function)
    {
        ParseAndValidateTestFunction(c_optional_edl_file_name, "RetOptionalUint8_t", FunctionKind::Untrusted, EdlTypeKind::Optional);
    }

    TEST_METHOD(Parse_RetOptionalUint16_t_Untrusted_Function)
    {
        ParseAndValidateTestFunction(c_optional_edl_file_name, "RetOptionalUint16_t", FunctionKind::Untrusted, EdlTypeKind::Optional);
    }

    TEST_METHOD(Parse_RetOptionalUint32_t_Untrusted_Function)
    {
        ParseAndValidateTestFunction(c_optional_edl_file_name, "RetOptionalUint32_t", FunctionKind::Untrusted, EdlTypeKind::Optional);
    }

    TEST_METHOD(Parse_RetOptionalUint64_t_Untrusted_Function)
    {
        ParseAndValidateTestFunction(c_optional_edl_file_name, "RetOptionalUint64_t", FunctionKind::Untrusted, EdlTypeKind::Optional);
    }

    TEST_METHOD(Parse_RetOptionalMyStruct_Untrusted_Function)
    {
        ParseAndValidateTestFunction(c_optional_edl_file_name, "RetOptionalMyStruct", FunctionKind::Untrusted, EdlTypeKind::Optional);
    }

    TEST_METHOD(Parse_RetOptionalMyEnum_Untrusted_Function)
    {
        ParseAndValidateTestFunction(c_optional_edl_file_name, "RetOptionalMyEnum", FunctionKind::Untrusted, EdlTypeKind::Optional);
    }

    TEST_METHOD(Parse_Edl_With_Optional_Type_Cycle_Function)
    {
        Assert::ExpectException<EdlAnalysisException>([&] ()
        {
            try
            {
                auto edl_parser = EdlParser(c_optional_cycles_edl_file_name, {});
                Edl edl = edl_parser.Parse();
            }
            catch (EdlAnalysisException& ex)
            {
                Assert::AreEqual(static_cast<std::uint32_t>(ErrorId::EdlOptionalCycle), static_cast<std::uint32_t>(ex.GetErrorId()));
                throw;
            }
        });
    }
};
}
