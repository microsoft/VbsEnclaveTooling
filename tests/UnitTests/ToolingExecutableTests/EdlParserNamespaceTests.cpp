// Copyright(c) Microsoft Corporation.
// Licensed under the MIT License.

#include <pch.h>
#include "CppUnitTest.h"
#include <CmdlineParsingHelpers.h>
#include <Edl\Parser.h>
#include <Edl\Utils.h>
#include "EdlParserTestHelpers.h"

#include <array>
#include <Exceptions.h>
#include <unordered_set>

using namespace ErrorHelpers;
using namespace ToolingExceptions;
using namespace EdlProcessor;
using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace VbsEnclaveToolingTests
{
    TEST_CLASS(EdlParserNamespaceTests)
    {
        private:

            std::filesystem::path m_nested_namespace_file_name = "NestedNamespaceTest.edl";

            std::filesystem::path m_double_namespace_file_name = "DoubleNamespaceTest.edl";

        public:


            TEST_METHOD(Parse_NestedNamespaceTest)
            {
                try
                {
                    auto edl_parser = EdlParser(m_nested_namespace_file_name);
                    Edl edl = edl_parser.Parse();
                    std::array<std::string, 7> namespaces =
                    {
                        "This",
                        "Is",
                        "A",
                        "Very",
                        "Long",
                        "Namespace",
                        "_1235_67890",
                    };

                    Namespace* actual_namespace = edl.m_namespace.get();
                    size_t namespace_count = 0;

                    for (auto& namespace_name : namespaces)
                    {
                        namespace_count++;
                        Assert::AreEqual(namespace_name, actual_namespace->m_name);
                        actual_namespace = actual_namespace->m_child.get();
                    }

                    Assert::AreEqual(namespaces.size(), namespace_count);
                    Assert::AreEqual(
                    std::string("This::Is::A::Very::Long::Namespace::_1235_67890"),
                    edl.m_namespace->QualifiedNamespaceName("::"));
                }
                catch (const std::exception& exception)
                {
                    auto error_message = ConvertExceptionMessageToWstring(exception);
                    Assert::Fail(error_message.c_str());
                }
            }

            TEST_METHOD(Parse_DoubleNamespaceTest)
            {
                Assert::ExpectException<ToolingExceptions::EdlAnalysisException>([&] ()
                {
                    auto edl_parser = EdlParser(m_double_namespace_file_name);
                    Edl edl = edl_parser.Parse();
                });
            }
    };
}
