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
#include <exception>

using namespace ErrorHelpers;
using namespace ToolingExceptions;
using namespace EdlProcessor;
using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace VbsEnclaveToolingTests
{

    TEST_CLASS(EdlParserImportTests)
    {
        private:
            std::filesystem::path m_base_imports_path = std::filesystem::current_path() / "TestFiles" / "ImportTestFiles";
            std::filesystem::path m_edl_file_without_duplicate_imports = m_base_imports_path / "ImportTest.edl";
            std::filesystem::path m_edl_file_with_duplicate_imports = m_base_imports_path / "DuplicateImports" / "A_Duplicate.edl";
            std::filesystem::path m_edl_file_with_cycle_imports = m_base_imports_path / "CycleImports" / "A_Cycle.edl";

            void ParseEdlFileWithImports(
                std::filesystem::path edl_file,
                std::vector<std::filesystem::path> import_directories,
                size_t trusted_function_list_size,
                size_t untrusted_function_list_size,
                std::unordered_set<std::string>& m_dev_type_names)
            {
                std::filesystem::path running_test_dir = std::filesystem::current_path();
                auto edl_parser = EdlParser(edl_file, import_directories);
                Edl edl = edl_parser.Parse();

                // Verify edl contains all functions from all the imported functions
                Assert::AreEqual(trusted_function_list_size, edl.m_trusted_functions.size());
                Assert::AreEqual(untrusted_function_list_size, edl.m_untrusted_functions.size());

                auto check_functions_expected = [&] (OrderedMap<std::string, Function>& functions)
                {
                    for (auto& [name, function] : functions)
                    {
                        auto& expected_signature = c_test_func_signatures.at(function.m_name);
                        Assert::AreEqual(expected_signature, function.GetDeclarationSignature());
                    }
                };

                check_functions_expected(edl.m_trusted_functions);
                check_functions_expected(edl.m_untrusted_functions);

                // Verify developer types were added to edl object
                Assert::AreEqual(m_dev_type_names.size(), edl.m_developer_types.size());
                for (auto& dev_type_name : edl.m_developer_types.keys())
                {
                    auto& dev_type = edl.m_developer_types.at(dev_type_name);
                    Assert::IsTrue(m_dev_type_names.contains(dev_type.m_name));
                }
            }

        public:

            // Trusted functions
        TEST_METHOD(Parse_edl_file_without_duplicate_or_cycle_imports)
        {
            std::unordered_set<std::string> m_dev_type_names =
            {
                "__anonymous_enum",
                "MyStruct1",
                "MyStruct0",
                "NonImportStruct",
                "NonImportEnum",
                "Color",
            };

            auto num_of_functions_to_parse = 31; // 31 trusted and 31 untrusted
            ParseEdlFileWithImports(
                m_edl_file_without_duplicate_imports,
                {std::filesystem::current_path()},
                num_of_functions_to_parse,
                num_of_functions_to_parse,
                m_dev_type_names);
        }

        TEST_METHOD(Parse_Edl_file_with_duplicate_imports)
        {
            std::unordered_set<std::string> m_dev_type_names =
            {
                "__anonymous_enum",
                "AEnum",
                "AStruct",
                "BEnum",
                "BStruct",
                "CEnum",
                "CStruct",
                "DEnum",
                "DStruct",
            };

            auto duplicate_dir = m_base_imports_path / "DuplicateImports";
                auto directories = {std::filesystem::current_path(), duplicate_dir};
                auto num_of_functions_to_parse = 4;// 4 trusted and 4 untrusted
                ParseEdlFileWithImports(
                    m_edl_file_with_duplicate_imports,
                    directories,
                    num_of_functions_to_parse,
                    num_of_functions_to_parse,
                    m_dev_type_names);
            }

            TEST_METHOD(Parse_Edl_file_with_cycle_in_imports)
            {
                auto cycle_dir = m_base_imports_path / "CycleImports";
                auto directories = {std::filesystem::current_path(), cycle_dir};
                auto edl_parser = EdlParser(m_edl_file_with_cycle_imports, directories);

                try
                {   
                    Edl edl = edl_parser.Parse();
                }
                catch (EdlAnalysisException& ex)
                {                    
                    Assert::AreEqual(static_cast<std::uint32_t>(ErrorId::ImportCycleFound), static_cast<std::uint32_t>(ex.GetErrorId()));
                }
            }

    };
}
