// <copyright placeholder>

// Do *not* #pragma once this file since it needs to take effect each time you include it.
//
// This header file removes access to the macros and functions that do WIL logging.
// Include it before defining functions that are used to handle WIL telemetry and logging
// to avoid trying to log telemetry while logging telemetry.
//
// If you get an error of the form
// "WIL_LOGGING_NOT_ALLOWED_HERE_USE_EXPECTED_VARIANT_INSTEAD is not defined" or
// "WIL_LOGGING_NOT_ALLOWED_HERE_USE_IMMEDIATE_VARIANT_INSTEAD is not defined",
// then replace your use of RETURN_BLAH with RETURN_BLAH_EXPECTED,
// and replace your use of FAIL_FAST_BLAH with FAIL_FAST_IMMEDIATE_BLAH.
// The EXPECTED/IMMEDIATE variants do not log.
//
// You cannot use THROW macros because they always log.

#pragma push_macro("__R_INFO")
#pragma push_macro("__R_INFO_ONLY")
#pragma push_macro("__R_INFO_NOFILE")
#pragma push_macro("__R_INFO_NOFILE_ONLY")
#pragma push_macro("__RFF_INFO")
#pragma push_macro("__RFF_INFO_ONLY")
#pragma push_macro("__RFF_INFO_NOFILE")
#pragma push_macro("__RFF_INFO_NOFILE_ONLY")

// Intentionally break the macros that are used to generate line information for logging,
// so that any attempt to do logging will result in build errors.
#undef __R_INFO
#undef __R_INFO_ONLY
#undef __R_INFO_NOFILE
#undef __R_INFO_NOFILE_ONLY
#undef __RFF_INFO
#undef __RFF_INFO_ONLY
#undef __RFF_INFO_NOFILE
#undef __RFF_INFO_NOFILE_ONLY

#define __R_INFO WIL_LOGGING_NOT_ALLOWED_HERE_USE_EXPECTED_VARIANT_INSTEAD
#define __R_INFO_ONLY WIL_LOGGING_NOT_ALLOWED_HERE_USE_EXPECTED_VARIANT_INSTEAD
#define __R_INFO_NOFILE WIL_LOGGING_NOT_ALLOWED_HERE_USE_EXPECTED_VARIANT_INSTEAD
#define __R_INFO_NOFILE_ONLY WIL_LOGGING_NOT_ALLOWED_HERE_USE_EXPECTED_VARIANT_INSTEAD
#define __RFF_INFO WIL_LOGGING_NOT_ALLOWED_HERE_USE_IMMEDIATE_VARIANT_INSTEAD
#define __RFF_INFO_ONLY WIL_LOGGING_NOT_ALLOWED_HERE_USE_IMMEDIATE_VARIANT_INSTEAD
#define __RFF_INFO_NOFILE WIL_LOGGING_NOT_ALLOWED_HERE_USE_IMMEDIATE_VARIANT_INSTEAD
#define __RFF_INFO_NOFILE_ONLY WIL_LOGGING_NOT_ALLOWED_HERE_USE_IMMEDIATE_VARIANT_INSTEAD
