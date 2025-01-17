// © Microsoft Corporation. All rights reserved.

#pragma once

#include "veil_arguments.any.h"

namespace veil::vtl1::implementation::exports
{
    HRESULT StartHelloSession(_Inout_ veil::any::implementation::args::StartHelloSession* params);
    HRESULT CreateAttestationReport(_Inout_ veil::any::implementation::args::CreateAttestationReport* params);
    HRESULT GenerateEncryptionKeySecuredByHello(_Inout_ veil::any::implementation::args::GenerateEncryptionKeySecuredByHello* params);
    HRESULT LoadEncryptionKeySecuredByHello(_Inout_ veil::any::implementation::args::LoadEncryptionKeySecuredByHello* params);

    HRESULT ExportKey(_Inout_ veil::any::implementation::args::ExportKey* params);
    HRESULT GetPackagedEnclaveIdentityProofChallenge(_Inout_ veil::any::implementation::args::GetPackagedEnclaveIdentityProofChallenge* params);

    HRESULT ValidatePackagedEnclaveIdentityProof(_Inout_ veil::any::implementation::args::ValidatePackagedEnclaveIdentityProof* params);
    HRESULT retrieve_enclave_error_for_thread(_Inout_ veil::any::implementation::args::retrieve_enclave_error_for_thread* params);
    HRESULT RegisterCallbacks(_Inout_ veil::any::implementation::args::RegisterCallbacks* params);
}
