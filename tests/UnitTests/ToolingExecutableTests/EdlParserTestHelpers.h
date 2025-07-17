#pragma once
// Copyright(c) Microsoft Corporation.
// Licensed under the MIT License.

#include <pch.h>
#include "CppUnitTest.h"
#include <CmdlineParsingHelpers.h>
#include <Edl\Parser.h>
#include <Edl\Utils.h>
#include <unordered_set>
#include <Exceptions.h>

using namespace ErrorHelpers;
using namespace ToolingExceptions;
using namespace EdlProcessor;
using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace VbsEnclaveToolingTests
{
    static std::filesystem::path m_array_edl_file_name = "TestFiles\\ArrayTest.edl";
    static std::filesystem::path m_basic_edl_file_name = "TestFiles\\BasicTypesTest.edl";
    static std::filesystem::path m_enum_edl_file_name = "TestFiles\\EnumTest.edl";
    static std::filesystem::path m_struct_edl_file_name = "TestFiles\\StructTest.edl";
    static std::filesystem::path c_edl_path_valid_input = "TestFiles\\BasicTypesTest.edl";

    static const std::unordered_map<std::string, std::string> c_test_func_signatures =
    {
        // ArrayTest.edl expected function signatures where key is function name and value is its signature

        {"ArrayChar", "ArrayChar(char[2],char[2],char[3])"},
        {"ArrayWchar_t", "ArrayWchar_t(wchar_t[2],wchar_t[2],wchar_t[3])"},
        { "ArrayFloat", "ArrayFloat(float[2],float[2],float[3])" },
        { "ArrayDouble", "ArrayDouble(double[2],double[2],double[3])" },
        { "ArraySize_t", "ArraySize_t(size_t[2],size_t[2],size_t[3])" },
        { "ArrayInt8_t", "ArrayInt8_t(int8_t[2],int8_t[2],int8_t[3])" },
        { "ArrayInt16_t", "ArrayInt16_t(int16_t[2],int16_t[2],int16_t[3])" },
        { "ArrayInt32_t", "ArrayInt32_t(int32_t[2],int32_t[2],int32_t[3])" },
        { "ArrayInt64_t", "ArrayInt64_t(int64_t[2],int64_t[2],int64_t[3])" },
        { "ArrayUint8_t", "ArrayUint8_t(uint8_t[2],uint8_t[2],uint8_t[3])" },
        { "ArrayUint16_t", "ArrayUint16_t(uint16_t[2],uint16_t[2],uint16_t[3])" },
        { "ArrayUint32_t", "ArrayUint32_t(uint32_t[2],uint32_t[2],uint32_t[3])" },
        { "ArrayUint64_t", "ArrayUint64_t(uint64_t[2],uint64_t[2],uint64_t[3])" },

        // BasicTypesTest.edl function signatures where key is function name and value is its signature
  
        {"TrustedWithBasicTypes", "TrustedWithBasicTypes(char,wchar_t,float,double,size_t,int8_t,int16_t,int32_t,int64_t,uint8_t,uint16_t,uint32_t,uint64_t)"},
        {"UntrustedWithBasicTypes", "UntrustedWithBasicTypes(char,wchar_t,float,double,size_t,int8_t,int16_t,int32_t,int64_t,uint8_t,uint16_t,uint32_t,uint64_t)"},
        {"RetChar", "RetChar()" },
        {"RetWchar_t", "RetWchar_t()" },
        { "RetFloat", "RetFloat()" },
        { "RetDouble", "RetDouble()" },
        { "RetSize_t", "RetSize_t()" },
        { "RetInt8_t", "RetInt8_t()" },
        { "RetInt16_t", "RetInt16_t()" },
        { "RetInt32_t", "RetInt32_t()" },
        { "RetInt64_t", "RetInt64_t()" },
        { "RetUint8_t", "RetUint8_t()" },
        { "RetUint16_t", "RetUint16_t()" },
        { "RetUint32_t", "RetUint32_t()" },
        { "RetUint64_t", "RetUint64_t()" },
        { "RetVoid", "RetVoid()" },

        // EnumTest.edl function signatures where key is function name and value is its signature

        {"TrustedGetColor", "TrustedGetColor(Color,Color[Nine],Color[5],Color[1],Color*,Color*,Color*,Color*,Color*,Color*,Color*,Color*,Color*,Color*,Color*,Color*,Color*,Color*,Color*,size_t,size_t)"},
        {"UntrustedGetColor", "UntrustedGetColor(Color,Color[5],Color[5],Color[1],Color*,Color*,Color*,Color*,Color*,Color*,Color*,Color*,Color*,Color*,Color*,Color*,Color*,Color*,Color*,size_t,size_t)"},

        // StructTest.edl function signatures where key is function name and value is its signature

        {"TrustedGetStruct1", "TrustedGetStruct1(MyStruct1,MyStruct1[5],MyStruct1[5],MyStruct1[1],MyStruct1*,MyStruct1*,MyStruct1*,MyStruct1*,MyStruct1*,MyStruct1*,MyStruct1*,MyStruct1*,MyStruct1*,MyStruct1*,MyStruct1*,MyStruct1*,MyStruct1*,MyStruct1*,MyStruct1*,size_t,size_t)"},
        {"UntrustedGetStruct1", "UntrustedGetStruct1(MyStruct1,MyStruct1[5],MyStruct1[5],MyStruct1[1],MyStruct1*,MyStruct1*,MyStruct1*,MyStruct1*,MyStruct1*,MyStruct1*,MyStruct1*,MyStruct1*,MyStruct1*,MyStruct1*,MyStruct1*,MyStruct1*,MyStruct1*,MyStruct1*,MyStruct1*,size_t,size_t)"},

        // ImportTest.edl function signatures where key is the function name and value is its signature
        { "NonImportFunc1", "NonImportFunc1()"},

        // A.edl function signatures where key is the function name and value is its signature
        { "AFunc", "AFunc()" },

        // B.edl function signatures where key is the function name and value is its signature
        { "BFunc", "BFunc()" },

        // C.edl function signatures where key is the function name and value is its signature
        { "CFunc", "CFunc()" },

        // D.edl function signatures where key is the function name and value is its signature
        { "DFunc", "DFunc()" },
    };

    static inline std::wstring ConvertExceptionMessageToWstring(const std::exception& exception)
    {
        std::wstringstream wstring_stream;
        wstring_stream << exception.what();
        return wstring_stream.str();
    }

    static inline Function GetParsedFunction(
        const std::filesystem::path& test_file_name,
        const std::string& function_name,
        const FunctionKind& function_kind)
    {
        auto edl_parser = EdlParser(test_file_name, {"."});
        Edl edl = edl_parser.Parse();

        // Verify function name
        Assert::AreEqual(edl.m_name, test_file_name.stem().generic_string());

        auto expected_signature = c_test_func_signatures.at(function_name);
        Function function;

        if (function_kind == FunctionKind::Trusted)
        {
            Assert::IsTrue(edl.m_trusted_functions.contains(expected_signature));
            function = edl.m_trusted_functions.at(expected_signature);
        }
        else
        {
            Assert::IsTrue(edl.m_untrusted_functions.contains(expected_signature));
            function = edl.m_untrusted_functions.at(expected_signature);
        }

         // Confirm function signature is expected signature.
        Assert::AreEqual(expected_signature, function.GetDeclarationSignature());
        return function;
        
    }

    static inline void ParseAndValidateTestFunction(
        const std::filesystem::path& test_file_name,
        const std::string& function_name,
        const FunctionKind& function_kind,
        const EdlTypeKind& expected_return_type)
    {
        try
        {
            Function function = GetParsedFunction(test_file_name, function_name, function_kind);

            // Confirm the function parameter names were parsed correctly.
            // test file function parameters are named arg<integer>, where integer is
            // the numeric position of the function parameter in the parameter list.
            std::uint32_t iteration = 1;
            for (auto& declaration : function.m_parameters)
            {
                std::string expected_parameter_name = std::format("arg{}", iteration++);
                Assert::AreEqual(expected_parameter_name, declaration.m_name);
            }

            // Confirm return type is correct
            auto actual_return_type_string = c_edlTypes_to_string_map.at(function.m_return_info.m_edl_type_info.m_type_kind);
            auto expected_return_type_string = c_edlTypes_to_string_map.at(expected_return_type);
            Assert::AreEqual(expected_return_type_string, actual_return_type_string);
        }
        catch (const std::exception& exception)
        {
            auto error_message = ConvertExceptionMessageToWstring(exception);
            Assert::Fail(error_message.c_str());
        }
    }
}
