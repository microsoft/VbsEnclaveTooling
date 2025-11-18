// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include "../../../../Common/veil_enclave_wil_inc/wil/enclave/wil_for_enclaves.h"

#include <winenclave.h>
#include <wchar.h>

#if __has_include(<veinterop_kcm.h>)
#include <veinterop_kcm.h>
#else
#include "..\veil_any_inc\veinterop_kcm_temp.h"
#endif
