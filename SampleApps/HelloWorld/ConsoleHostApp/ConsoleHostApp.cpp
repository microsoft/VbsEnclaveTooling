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

    auto flags = EnclaveCreate_Flags;

    #ifndef _DEBUG
        static_assert(flags & ENCLAVE_VBS_FLAG_DEBUG == 0, "ERROR: Do not use DEBUG flag for retail builds");
    #endif

    // Memory allocation must match enclave configuration (512mb)
    auto enclave = veil::vtl0::enclave::create(ENCLAVE_TYPE_VBS, ownerId, flags, veil::vtl0::enclave::megabytes(512));
    veil::vtl0::enclave::load_image(enclave.get(), L"MySecretVBSEnclave.dll");
    veil::vtl0::enclave::initialize(enclave.get(), 1);

    // Register framework callbacks
    veil::vtl0::enclave_api::register_callbacks(enclave.get());

    // Initialize enclave interface
    auto enclaveInterface = VbsEnclave::VTL0_Stubs::MySecretEnclave(enclave.get());
    THROW_IF_FAILED(enclaveInterface.RegisterVtl0Callbacks());

    //Call into the enclave
    auto secretResults = enclaveInterface.DoSecretMath(10, 20);
    wprintf(L"Result = %d\n", secretResults);
    wprintf(L"Press any key to exit.");
    _getch();

}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
