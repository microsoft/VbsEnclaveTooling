// © Microsoft Corporation. All rights reserved.

#pragma once

//#include "shared_enclave.h"
#include "veil_arguments.any.h"

HRESULT VerifyStartHelloSessionParameters(
    _In_ const veil::any::implementation::args::StartHelloSession* params, _Inout_ veil::any::implementation::args::StartHelloSession& startSessionHandshake);
HRESULT VerifyGenerateEncryptionKeySecuredByHelloParameters(
    _In_ const veil::any::implementation::args::GenerateEncryptionKeySecuredByHello* params, _Inout_ veil::any::implementation::args::GenerateEncryptionKeySecuredByHello& startSessionHandshake);
HRESULT Verify_EnclaveSdk_LoadEncryptionKeySecuredByHello_Parameters(_In_ const veil::any::implementation::args::LoadEncryptionKeySecuredByHello* params, _Inout_ veil::any::implementation::args::LoadEncryptionKeySecuredByHello& finishLoadRecallKey);
