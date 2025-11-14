// FuzzTests.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <string>
#include <vector>
#include <cstdint>
#include <windows.h>

// Include VBS Enclave headers
#include <VbsEnclave\HostApp\Stubs\Trusted.h>
#include <veil\host\enclave_api.vtl0.h>
#include <wil/resource.h>
#include <wil/result_macros.h>

extern "C" __declspec(dllexport) void* TestFunc(void* function_context);

#define FUZZ_EXPORT __declspec(dllexport)

// Structure to represent fuzzing input parameters
struct FuzzInput {
    uint32_t activity_level;        // Activity level for logging (1-5)
    uint32_t logFilePathLength;     // Length of log file path string in bytes
    // Variable length data follows: logFilePath
};

// Global enclave instance for fuzzing
static veil::vtl0::unique_enclave g_enclave;
static bool g_enclaveInitialized = false;
extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv)
{
    std::vector<uint8_t> ownerId = {};
    return 0;
}


// Helper function to initialize the enclave once
bool InitializeEnclaveForFuzzing() {
    if (g_enclaveInitialized) {
        return true;
    }

    try {
        // Create app+user enclave identity
        std::vector<uint8_t> ownerId = {};
            
        TestFunc(NULL);
        auto enclave_module = GetModuleHandleW(L"sampleenclave.dll");

        // Register framework callbacks
        veil::vtl0::enclave_api::register_callbacks(reinterpret_cast<void*>(enclave_module));

        g_enclaveInitialized = true;
        std::wcout << L"Enclave initialized successfully for fuzzing" << std::endl;
        return true;
    }
    catch (const std::exception& e) {
        std::string error_msg = e.what();
        std::wstring werror_msg(error_msg.begin(), error_msg.end());
        std::wcout << L"Failed to initialize enclave for fuzzing: " << werror_msg << std::endl;
        g_enclaveInitialized = false;
        return false;
    }
    catch (...) {
        std::wcout << L"Failed to initialize enclave for fuzzing: Unknown exception" << std::endl;
        g_enclaveInitialized = false;
        return false;
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // This function is called by the fuzzer with the input data.
    // We'll use it to fuzz RunEncryptionKeyExample_CreateEncryptionKey function.

    std::cout << "In LLVMFuzzerTestOneInput." << std::endl;

    if (size < sizeof(FuzzInput)) {
        return 0; // Input too small
    }

    // Initialize enclave if not already done
    if (!InitializeEnclaveForFuzzing()) {
        return 0; // Enclave initialization failed
    }

    const FuzzInput* fuzzInput = reinterpret_cast<const FuzzInput*>(data);
    
    // Validate input parameters
    if (fuzzInput->activity_level == 0 || fuzzInput->activity_level > 5) {
        return 0; // Invalid activity level (should be 1-5)
    }
    
    if (fuzzInput->logFilePathLength > 1024) {
      return 0; // Unreasonably large log file path
    }
    
    size_t expectedSize = sizeof(FuzzInput) + fuzzInput->logFilePathLength;
    
    if (size < expectedSize) {
        return 0; // Input size doesn't match expected parameters
    }

    // Extract variable-length data
    const uint8_t* dataPtr = data + sizeof(FuzzInput);
    
    // Extract logFilePath
    std::wstring logFilePath;
    if (fuzzInput->logFilePathLength > 0 && fuzzInput->logFilePathLength % 2 == 0) {
        // Treat as wide characters
        const wchar_t* logFilePathPtr = reinterpret_cast<const wchar_t*>(dataPtr);
        logFilePath = std::wstring(logFilePathPtr, fuzzInput->logFilePathLength / sizeof(wchar_t));
    } 
    else {
        logFilePath = L"FuzzTest.log"; // Fallback log file
    }

    // Output parameter for the function
    std::vector<std::uint8_t> securedEncryptionKeyBytes;

    try {
        // Initialize enclave interface (using real enclave)
        auto enclaveInterface = VbsEnclave::Trusted::Stubs::SampleEnclave(g_enclave.get());
        HRESULT registerResult = enclaveInterface.RegisterVtl0Callbacks();

        if (FAILED(registerResult)) {
            std::wcout << L"Failed to register VTL0 callbacks, HRESULT: 0x" 
            << std::hex << registerResult << std::endl;
            return 0;
        }

        // Call the actual target function through the proper enclave interface
        HRESULT result = enclaveInterface.RunEncryptionKeyExample_CreateEncryptionKey(
            fuzzInput->activity_level,
            logFilePath,
            securedEncryptionKeyBytes
        );

        // Log the result (in a real fuzzing scenario, you might want to suppress output)
        if (SUCCEEDED(result)) {
            // Function succeeded - this is good for fuzzing
            std::wcout << L"RunEncryptionKeyExample_CreateEncryptionKey succeeded with key size: " 
            << securedEncryptionKeyBytes.size() << std::endl;
        } 
        else {
            // Function failed - this is also valid behavior to test
            std::wcout << L"RunEncryptionKeyExample_CreateEncryptionKey failed with HRESULT: 0x" 
            << std::hex << result << std::endl;
        }
    }
    catch (const std::exception& e) {
        // Catch any exceptions - fuzzing should not crash the process
        std::string error_msg = e.what();
        std::wstring werror_msg(error_msg.begin(), error_msg.end());
        std::wcout << L"Exception caught during RunEncryptionKeyExample_CreateEncryptionKey execution: " << werror_msg << std::endl;
    }
    catch (...) {
        // Catch any exceptions - fuzzing should not crash the process
        std::wcout << L"Unknown exception caught during RunEncryptionKeyExample_CreateEncryptionKey execution" << std::endl;
    }

    // Return 0 to indicate successful processing of the input.
    return 0;
}
