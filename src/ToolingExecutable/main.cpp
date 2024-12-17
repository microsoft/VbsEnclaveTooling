// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <pch.h>
#include <CmdlineParsingHelpers.h>
#include <CmdlineArgumentsParser.h>

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
    
    return S_OK;
}
