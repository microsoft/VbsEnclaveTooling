// ConsoleHostApp.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <conio.h>
#include <iostream>
#include <veil\host\enclave_api.vtl0.h>
#include <veil\host\logger.vtl0.h>
#include <VbsEnclave\HostApp\Stubs.h>

int main()
{
    std::cout << "Hello World!\n";

    /******************************* Enclave setup *******************************/

    // Create app+user enclave identity
    auto ownerId = veil::vtl0::appmodel::owner_id();

    // Load enclave
    // We don't want DEBUG for a retail build!
    constexpr int EnclaveCreate_Flags{
    #ifdef _DEBUG
        ENCLAVE_VBS_FLAG_DEBUG
    #endif
    };

    #ifndef _DEBUG
    static_assert((EnclaveCreate_Flags & ENCLAVE_VBS_FLAG_DEBUG) == 0, "ERROR: Do not use _DEBUG flag for retail builds");
    #endif

    // Memory allocation must match enclave configuration (512mb)
    auto enclave = veil::vtl0::enclave::create(ENCLAVE_TYPE_VBS, ownerId, EnclaveCreate_Flags, veil::vtl0::enclave::megabytes(512));
    veil::vtl0::enclave::load_image(enclave.get(), L"MySecretVBSEnclave.dll");
    veil::vtl0::enclave::initialize(enclave.get(), 1);

    // Register framework callbacks
    veil::vtl0::enclave_api::register_callbacks(enclave.get());

    // Initialize enclave interface. Note that MySecretEnclave is a codegen generated class.
    auto enclaveInterface = VbsEnclave::VTL0_Stubs::MySecretEnclave(enclave.get());
    THROW_IF_FAILED(enclaveInterface.RegisterVtl0Callbacks());

    //Call into the enclave
    auto secretResults = enclaveInterface.DoSecretMath(10, 20);
    wprintf(L"Result = %d\n", secretResults);
    wprintf(L"Press any key to exit.");
    _getch();
}
