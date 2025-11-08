// pch.h: This is a precompiled header file.
// Files listed below are compiled only once, improving build performance for future builds.
// This also affects IntelliSense performance, including code completion and many code browsing features.
// However, files listed here are ALL re-compiled if any one of them is updated between builds.
// Do not add files here that you will be updating frequently as this negates the performance advantage.

#ifndef PCH_H
#define PCH_H

// Include the wil_for_enclave header file. This is needed so you can use the 
// Windows Implementation Library and other Windows #defines that appear in dllmain.cpp
// You can also access Windows Macros via the windows.h header.
#include <wil\enclave\wil_for_enclaves.h>

#endif //PCH_H
