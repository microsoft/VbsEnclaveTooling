// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "mbedtls/mbedtls_config.h"

#undef MBEDTLS_NET_C
#undef MBEDTLS_FS_IO
#undef MBEDTLS_HAVE_TIME
#undef MBEDTLS_HAVE_TIME_DATE
#undef MBEDTLS_TIMING_C
#undef MBEDTLS_PSA_ITS_FILE_C
#undef MBEDTLS_PSA_CRYPTO_STORAGE_C
#undef MBEDTLS_SELF_TEST
#undef MBEDTLS_DEBUG_C

#define MBEDTLS_TEST_SW_INET_PTON
