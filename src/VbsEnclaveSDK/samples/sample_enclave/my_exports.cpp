// <copyright placeholder>

#include "pch.h"

#include <array>
#include <stdexcept>

#include <enclave_interface.vtl1.h>
#include <vtl0_functions.vtl1.h>

#include "sample_arguments.any.h"

/*
* My app exports: My app-enclave's exports
*/
ENCLAVE_FUNCTION MySaveScreenshotExport(_In_ PVOID params)
{
    (void)params;

    // ..code here..

    return 0;
}

/*
* Some sample code
*/

void RunTaskpoolExampleImpl(_In_ PVOID)
{
    veil::vtl1::vtl0_functions::print_wstring(L"HELLO FROM SAMPLE ENCLAVE");
}

ENCLAVE_FUNCTION RunTaskpoolExample(_In_ PVOID pv) try
{
    // TODO: Use tooling codegen to create your exports, or manually use the
    // vtl0_ptr secure pointers.
    // RunTaskpoolExampleImpl(vtl0_ptr<RunTaslpoolExampleArgs>(pv));
    RunTaskpoolExampleImpl(pv);
    return nullptr;
}
catch (...)
{
    LOG_CAUGHT_EXCEPTION();
    RETURN_HR_AS_PVOID(wil::ResultFromCaughtException());
}
