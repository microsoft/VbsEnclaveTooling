// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "pch.h"

#include <iostream>
#include <string_view>

#include <wil/win32_helpers.h>

#include "samples.h"

int
wmain([[maybe_unused]] _In_ int argc, [[maybe_unused]] _In_reads_(argc) wchar_t** argv)
try
{
    if (argc != 2)
    {
        std::wcerr << L"Usage: " << argv[0] << L"--taskpool" << std::endl;
        THROW_HR(E_INVALIDARG);
    }

    std::wstring_view arg = argv[1];

    if (arg == L"--taskpool")
    {
        Samples::Taskpool::main();
    }
    else
    {
        std::wcerr << L"Invalid argument. Use --taskpool." << std::endl;
        THROW_HR(E_INVALIDARG);
    }

    std::wcout << std::endl;
    std::cout << "Press any key to continue...";
    std::cin.get();
    return 0;
}
catch (std::exception const& e)
{
    auto hr = wil::ResultFromCaughtException();
    std::wcerr << L"0x" << std::hex << hr << std::endl;

    // Also spit out the error
    std::wcerr << e.what() << std::endl;

    std::cout << "Press any key to continue...";
    std::cin.get();
    return hr;
}
catch (...)
{
    auto hr = wil::ResultFromCaughtException();
    std::wcerr << L"0x" << std::hex << hr << std::endl;

    std::cout << "Press any key to continue...";
    std::cin.get();
    return hr;
}
