// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <pch.h>
#include "CppUnitTest.h"
#include <Edl\Parser.h>
#include <CodeGeneration\Rust\CodeGenerationHelpers.h>

using namespace EdlProcessor;
using namespace CmdlineParsingHelpers;
using namespace CodeGeneration::Rust;
using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace VbsEnclaveToolingTests
{
    // These tests guard the Rust code generation for out-only struct/wstring
    // parameters. Such parameters are Option<T> in the ABI and are None on
    // entry, so the generator must:
    //   * dispatch:  insert a default (never .as_mut().expect(...), which would
    //                panic/loop in a no_std enclave on the normal None case), and
    //   * extract:   surface a missing field as an AbiError via ok_or(...)? rather
    //                than .expect(...), because the returned value is produced by
    //                the untrusted other side of the ABI.
    // Reverting either fix would fail these tests.

    static const std::filesystem::path c_out_param_edl = "TestFiles\\OutParamCodeGenTest.edl";

    static Function FindFunctionByName(
        const OrderedMap<std::string, Function>& functions,
        const std::string& name)
    {
        for (auto& function : functions.values())
        {
            if (function.m_name == name)
            {
                return function;
            }
        }

        Assert::Fail(L"Expected function was not found in the parsed EDL.");
    }

    static Function ParseTrustedFunction()
    {
        EdlParser parser(c_out_param_edl, { "." });
        Edl edl = parser.Parse();
        return FindFunctionByName(edl.m_trusted_functions, "TrustedOutParams");
    }

    static Function ParseUntrustedFunction()
    {
        EdlParser parser(c_out_param_edl, { "." });
        Edl edl = parser.Parse();
        return FindFunctionByName(edl.m_untrusted_functions, "UntrustedOutParams");
    }

    static bool Contains(const std::string& haystack, const std::string& needle)
    {
        return haystack.find(needle) != std::string::npos;
    }

    TEST_CLASS(CodeGenerationRustOutParamTests)
    {
    public:

        // Dispatch closure: out-only struct/wstring must be inserted (not
        // unwrapped with .expect), while an [in, out] struct is a plain borrow.
        TEST_METHOD(Dispatch_OutStructAndWString_UseInsert_NotExpect)
        {
            Function function = ParseTrustedFunction();
            std::string closure = GetClosureFunctionStatement(function, VirtualTrustLayerKind::Enclave);

            Assert::IsTrue(Contains(closure, "abi_type.m_struct_out.insert(Default::default())"),
                L"Out struct param should be inserted with a default.");
            Assert::IsTrue(Contains(closure, "abi_type.m_wstring_out.insert(Default::default())"),
                L"Out wstring param should be inserted with a default.");
            Assert::IsTrue(Contains(closure, "&mut abi_type.m_struct_inout"),
                L"In/out struct param should be a plain mutable borrow.");

            Assert::IsFalse(Contains(closure, ".expect("),
                L"Dispatch must not unwrap an out-param Option with .expect().");
            Assert::IsFalse(Contains(closure, "get_or_insert_with"),
                L"Out-only params must overwrite (insert), not preserve caller contents.");
        }

        // Extraction: out-only struct/wstring must be surfaced as an AbiError on
        // a missing field, while an [in, out] struct is a plain move.
        TEST_METHOD(Extract_OutStructAndWString_UseOkOr_NotExpect)
        {
            Function function = ParseTrustedFunction();
            std::string extraction =
                GetMoveFromAbiStructToParamStatements(0, "edlcodegen_enclave", function.m_parameters);

            Assert::IsTrue(Contains(extraction,
                "result.m_struct_out.ok_or(edlcodegen_enclave::AbiError::Hresult(0x80070057u32 as i32))?"),
                L"Out struct param should be extracted with ok_or(E_INVALIDARG)?.");
            Assert::IsTrue(Contains(extraction,
                "result.m_wstring_out.ok_or(edlcodegen_enclave::AbiError::Hresult(0x80070057u32 as i32))?"),
                L"Out wstring param should be extracted with ok_or(E_INVALIDARG)?.");
            Assert::IsTrue(Contains(extraction, "*struct_inout = result.m_struct_inout;"),
                L"In/out struct param should be a plain move.");

            Assert::IsFalse(Contains(extraction, ".expect("),
                L"Extraction must not unwrap an out-param Option with .expect().");
        }

        // The generator emits the crate-appropriate error path for the host side.
        TEST_METHOD(Extract_HostDirection_UsesHostCrate)
        {
            Function function = ParseUntrustedFunction();
            std::string extraction =
                GetMoveFromAbiStructToParamStatements(0, "edlcodegen_host", function.m_parameters);

            Assert::IsTrue(Contains(extraction,
                "result.m_struct_out.ok_or(edlcodegen_host::AbiError::Hresult(0x80070057u32 as i32))?"),
                L"Host extraction should reference edlcodegen_host::AbiError.");
            Assert::IsFalse(Contains(extraction, ".expect("),
                L"Extraction must not unwrap an out-param Option with .expect().");
        }
    };
}
