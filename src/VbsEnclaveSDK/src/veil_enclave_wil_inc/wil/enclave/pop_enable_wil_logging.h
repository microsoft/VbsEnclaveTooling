// <copyright placeholder>

// Do *not* #pragma once this file since it needs to take effect each time you include it.
//
// This header file restores access to the macros and functions that do WIL logging.
// It undoes push_disable_wil_logging.h

#pragma pop_macro("__R_INFO")
#pragma pop_macro("__R_INFO_ONLY")
#pragma pop_macro("__R_INFO_NOFILE")
#pragma pop_macro("__R_INFO_NOFILE_ONLY")
#pragma pop_macro("__RFF_INFO")
#pragma pop_macro("__RFF_INFO_ONLY")
#pragma pop_macro("__RFF_INFO_NOFILE")
#pragma pop_macro("__RFF_INFO_NOFILE_ONLY")
