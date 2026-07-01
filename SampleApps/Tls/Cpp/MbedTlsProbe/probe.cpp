// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "tls_enclave_mbedtls_config.h"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ssl.h>
#include <mbedtls/version.h>
#include <psa/crypto.h>

extern "C" __declspec(dllexport) int MbedTlsProbe_Run()
{
    constexpr unsigned char personalization[] = "vbs-enclave-tls-sample";

    if (psa_crypto_init() != PSA_SUCCESS)
    {
        return 10;
    }

    mbedtls_ssl_context ssl;
    mbedtls_ssl_config config;
    mbedtls_ctr_drbg_context ctrDrbg;
    mbedtls_entropy_context entropy;

    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&config);
    mbedtls_ctr_drbg_init(&ctrDrbg);
    mbedtls_entropy_init(&entropy);

    const int seedResult = mbedtls_ctr_drbg_seed(
        &ctrDrbg,
        mbedtls_entropy_func,
        &entropy,
        personalization,
        sizeof(personalization) - 1);

    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctrDrbg);
    mbedtls_ssl_config_free(&config);
    mbedtls_ssl_free(&ssl);
    mbedtls_psa_crypto_free();

    return seedResult == 0 ? 0 : 20;
}
