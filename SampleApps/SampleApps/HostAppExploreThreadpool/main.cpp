#include <iostream>
#include <conio.h>

#include <windows.h>
#include <wil/resource.h>
#include <wil/result_macros.h>

#include <veil\host\enclave_api.vtl0.h>

#include <VbsEnclave\HostApp\Stubs\Trusted.h>

int main(int argc, char* argv[])
{
    wil::SetResultLoggingCallback([] (wil::FailureInfo const& failure) noexcept
    {
        wchar_t message[1024];
        wil::GetFailureLogString(message, ARRAYSIZE(message), failure);
        wprintf(L"Diagnostic message: %ls\n", message);
    });

    std::wcout << L"Running sample: Taskpool..." << std::endl;

    std::vector<uint8_t> ownerId = {};
    auto flags = ENCLAVE_VBS_FLAG_DEBUG;

    constexpr DWORD THREAD_COUNT = 3;

    auto enclave = veil::vtl0::enclave::create(ENCLAVE_TYPE_VBS, ownerId, flags, veil::vtl0::enclave::megabytes(512));
    veil::vtl0::enclave::load_image(enclave.get(), L"sampleenclave.dll");
    veil::vtl0::enclave::initialize(enclave.get(), THREAD_COUNT);

    veil::vtl0::enclave_api::register_callbacks(enclave.get());

    auto enclaveInterface = VbsEnclave::Trusted::Stubs::SampleEnclave(enclave.get());
    THROW_IF_FAILED(enclaveInterface.RegisterVtl0Callbacks());

    THROW_IF_FAILED(enclaveInterface.RunTaskpoolExample(THREAD_COUNT - 1));

    std::wcout << L"Finished sample: Taskpool..." << std::endl;

    std::cout << "\n\nPress any key to exit..." << std::endl;
    _getch();

    return 0;
}
