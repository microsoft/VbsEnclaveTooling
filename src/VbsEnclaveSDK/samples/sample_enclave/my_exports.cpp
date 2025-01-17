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

using namespace veil::vtl1::vtl0_functions;


ENCLAVE_FUNCTION RunTaskpoolExample(_In_ PVOID) try
{
    print_wstring(L"HELLO FROM SAMPLE ENCLAVE");

    RETURN_HR_AS_PVOID(S_OK);
}
catch (...)
{
    RETURN_HR_AS_PVOID(wil::ResultFromCaughtException());
}
