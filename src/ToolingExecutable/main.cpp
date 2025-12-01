// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <pch.h>
#include <CmdlineParsingHelpers.h>
#include <CmdlineArgumentsParser.h>
#include <Edl\Parser.h>
#include <CodeGeneration\Cpp\CodeGeneration.h>
#include <CodeGeneration\Common\Types.h>
#include <CodeGeneration\Rust\CodeGeneration.h>
#include <wil\result_macros.h>

using namespace EdlProcessor;
using namespace CmdlineParsingHelpers;
using namespace CodeGeneration::Cpp;
using namespace CodeGeneration::Rust;

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
        auto edl_parser = EdlParser(argument_parser.EdlFilePath(), argument_parser.ImportDirectories());
        Edl edl = edl_parser.Parse();

        auto metadata = CmdlineMetadata(
            std::move(edl),
            argument_parser.OutDirectory(),
            argument_parser.ErrorHandling(),
            argument_parser.VirtualTrustLayer(),
            argument_parser.GeneratedNamespace(),
            argument_parser.Vtl0ClassName(),
            argument_parser.FlatbufferCompiler(),
            argument_parser.SupportedLanguage());

        if (metadata.language_kind == SupportedLanguageKind::Cpp)
        {
            CppCodeGenerator(metadata).Generate();
        }
        else if (metadata.language_kind == SupportedLanguageKind::Rust)
        {
            RustCodeGenerator(metadata).Generate();
        }
        
        auto output_path = argument_parser.OutDirectory().empty() ?
            std::filesystem::current_path() :
            argument_parser.OutDirectory();

        auto success_message = std::format(
            "Code generated to output folder: {}",
            output_path.generic_string());

        PrintStatus(Status::Info, success_message);
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
