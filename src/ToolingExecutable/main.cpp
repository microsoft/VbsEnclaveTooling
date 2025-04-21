// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <pch.h>
#include <CmdlineParsingHelpers.h>
#include <CmdlineArgumentsParser.h>
#include <Edl\Parser.h>
#include <CodeGeneration\CodeGeneration.h>
#include <wil\result_macros.h>

using namespace EdlProcessor;
using namespace CmdlineParsingHelpers;
using namespace CodeGeneration;


int main(int argc, char* argv[])
{
    auto argument_parser = CmdlineArgumentsParser(argc, argv);

    // Only proceed with valid arguments
    if (!argument_parser.ParseSuccessful())
    {
        PrintUsage();
        PrintHresult(ErrorId::GeneralFailure, E_INVALIDARG);
        return E_INVALIDARG;
    }

    if (argument_parser.ShouldDisplayHelp())
    {
        PrintUsage();
        return S_OK;
    }

    try
    {
        auto edl_parser = EdlParser(argument_parser.EdlFilePath());
        Edl edl = edl_parser.Parse();
        std::optional<Edl> sdk_edl{};

        if (argument_parser.ShouldAddSdkLinkage())
        {
            auto sdk_edl_parser = EdlParser(GetInternalSdkEdlFile());
            sdk_edl = sdk_edl_parser.Parse();
        }

        auto cpp_code_generator = CppCodeGenerator(
            std::move(edl),
            sdk_edl,
            argument_parser.OutDirectory(),
            argument_parser.ErrorHandling(),
            argument_parser.VirtualTrustLayer(),
            argument_parser.GeneratedNamespace(),
            argument_parser.Vtl0ClassName(),
            argument_parser.FlatbufferCompiler());

        cpp_code_generator.Generate();
    }
    catch (const std::exception& exception)
    {
        PrintError(exception.what());
        auto hr = wil::ResultFromCaughtException();
        PrintHresult(ErrorId::GeneralFailure, hr);
        return hr;
    }
    catch (...)
    {
        auto hr = wil::ResultFromCaughtException();
        PrintHresult(ErrorId::GeneralFailure, hr);
        return hr;
    }

    return S_OK;
}
