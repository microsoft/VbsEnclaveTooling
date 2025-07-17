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
    public:

    // Trusted functions
    TEST_METHOD(Parse_TrustedGetColor_Function)
    {
        ParseAndValidateTestFunction(m_enum_edl_file_name, "TrustedGetColor", FunctionKind::Trusted, EdlTypeKind::Enum);
    }

    // Untrusted functions

    TEST_METHOD(Parse_UntrustedGetColor_Function)
    {
        ParseAndValidateTestFunction(m_enum_edl_file_name, "UntrustedGetColor", FunctionKind::Untrusted, EdlTypeKind::Enum);
    }    
};
}
