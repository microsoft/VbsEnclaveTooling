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

TEST_CLASS(EdlParserStructTypeTests)
{
    private:

    std::filesystem::path m_struct_edl_file_name = "StructTest.edl";
    public:

    // Trusted functions
    TEST_METHOD(Parse_TrustedGetStruct1_Function)
    {
        ParseAndValidateTestFunction(m_struct_edl_file_name, "TrustedGetStruct1", FunctionKind::Trusted, EdlTypeKind::Struct);
    }

    TEST_METHOD(Parse_TrustedGetStruct1Ptr_Function)
    {
        ParseAndValidateTestFunction(m_struct_edl_file_name, "GetStruct1Ptr", FunctionKind::Trusted, EdlTypeKind::Struct, FunctionReturnKind::Ptr);
    }

    // Untrusted functions

    TEST_METHOD(Parse_UntrustedGetStruct1_Function)
    {
        ParseAndValidateTestFunction(m_struct_edl_file_name, "UntrustedGetStruct1", FunctionKind::Untrusted, EdlTypeKind::Struct);
    }

    TEST_METHOD(Parse_UntrustedGetStruct1Ptr_Function)
    {
        ParseAndValidateTestFunction(m_struct_edl_file_name, "GetStruct1Ptr", FunctionKind::Untrusted, EdlTypeKind::Struct, FunctionReturnKind::Ptr);
    }
};
}
