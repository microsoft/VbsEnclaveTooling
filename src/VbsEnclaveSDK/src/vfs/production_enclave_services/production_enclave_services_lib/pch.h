// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <Unknwn.h>
#include <atomic>
#include <safeint.h>
#include <unordered_map>
#include <string>
#include <vector>
#include <map>
#include <vector>
#include <array>

#include <bcrypt.h>

#include "data_enclave.h"

#include <ntenclv.h>
#include <enclaveium.h>
#include <winenclaveapi.h>
#include "EnclaveServices.h"

#define FEATURE_STAGING_LEGACY_MODE
// #include <FeatureStaging-modeHelpers.h>
