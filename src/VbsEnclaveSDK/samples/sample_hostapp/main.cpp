
#include "pch.h"

#include <iostream>
#include <string_view>

#include <wil/win32_helpers.h>

#include "samples.h"

int
wmain([[maybe_unused]] _In_ int argc, [[maybe_unused]] _In_reads_(argc) wchar_t** argv)
try
{
    /*
    // Print diagnostic messages to the console for developer convenience.
    wil::SetResultLoggingCallback([](wil::FailureInfo const& failure) noexcept
    {
        wchar_t message[1024];
        wil::GetFailureLogString(message, ARRAYSIZE(message), failure);
        wprintf(L"Diagnostic message: %ls\n", message);
    });
    */

    if (argc <= 1)
    {
        Samples::Taskpool::main();
    }
    else
    {
        THROW_HR_MSG(E_INVALIDARG, "Specify a sample");
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
