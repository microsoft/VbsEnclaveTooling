#include "pch.h"

#include <iostream>

#include <enclave_api.vtl0.h>

#include <sample_arguments.any.h>

namespace Samples::Taskpool
{
    void main()
    {
        std::wcout << L"Running sample: Taskpool..." << std::endl;

        // Create app+user enclave identity
        auto ownerId = veil::vtl0::appmodel::owner_id();

        // Load enclave
        auto flags = ENCLAVE_VBS_FLAG_DEBUG;

        // Let's arbitrarily choose to spawn 3 threads
        constexpr DWORD THREAD_COUNT = 3;

        auto enclave = veil::vtl0::enclave::create(ENCLAVE_TYPE_VBS, ownerId, flags, veil::vtl0::enclave::megabytes(512));
        veil::vtl0::enclave::load_image(enclave.get(), L"sample_enclave.dll");
        veil::vtl0::enclave::initialize(enclave.get(), THREAD_COUNT);

        // Register framework callbacks
        veil::vtl0::enclave_api::register_callbacks(enclave.get());

        // Call into enclave to 'RunTaskpoolExample' export
        sample::args::RunTaskpoolExample data;
        data.threadCount = THREAD_COUNT - 1;
        THROW_IF_FAILED(veil::vtl0::enclave::call_enclave(enclave.get(), "RunTaskpoolExample", data));

        std::wcout << L"Finished sample: Taskpool..." << std::endl;
    }
}
