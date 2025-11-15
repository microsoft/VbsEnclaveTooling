// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <windows.h>
#include <stdio.h>
#include <wil/resource.h>
#include <wil/result_macros.h>

#if __has_include(<veinterop_kcm.h>)
#include <veinterop_kcm.h>
#else
#include "..\veil_any_inc\veinterop_kcm_temp.h"
#endif
