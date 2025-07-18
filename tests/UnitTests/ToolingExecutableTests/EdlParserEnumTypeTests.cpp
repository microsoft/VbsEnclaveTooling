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

TEST_CLASS(EdlParserEnumTypeTests)
{
    private:

    std::filesystem::path m_enum_edl_file_name = "EnumTest.edl";

    public:

    // Trusted functions
    TEST_METHOD(Parse_TrustedGetColor_Function)
    {
        ParseAndValidateTestFunction(m_enum_edl_file_name, "TrustedGetColor", FunctionKind::Trusted, EdlTypeKind::Enum);
    }

    TEST_METHOD(Parse_TrustedGetColorPtr_Function)
    {
        ParseAndValidateTestFunction(m_enum_edl_file_name, "GetColorPtr", FunctionKind::Trusted, EdlTypeKind::Enum, FunctionReturnKind::Ptr);
    }

    // Untrusted functions

    TEST_METHOD(Parse_UntrustedGetColor_Function)
    {
        ParseAndValidateTestFunction(m_enum_edl_file_name, "UntrustedGetColor", FunctionKind::Untrusted, EdlTypeKind::Enum);
    }    

    TEST_METHOD(Parse_UntrustedGetColorPtr_Function)
    {
        ParseAndValidateTestFunction(m_enum_edl_file_name, "GetColorPtr", FunctionKind::Untrusted, EdlTypeKind::Enum, FunctionReturnKind::Ptr);
    }
};
}
