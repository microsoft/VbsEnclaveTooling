// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <pch.h>
#include <CmdlineParsingHelpers.h>
#include <CmdlineArgumentsParser.h>
#include <Edl\Parser.h>

using namespace EdlProcessor;
using namespace CmdlineParsingHelpers;

int main(int argc, char* argv[])
{
    auto argument_parser = CmdlineArgumentsParser(argc, argv);
    
    // Only proceed with valid arguments
    if (!argument_parser.ParseSuccessful())
    {
        PrintUsage();
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
    }
    catch (const std::exception& exception)
    {
        PrintStatus(Status::Error, exception.what());
        return E_FAIL;
    }

    return S_OK;
}
