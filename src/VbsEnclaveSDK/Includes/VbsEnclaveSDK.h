// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

// Add guards so name mangling is consistent when consuming in C or C++. 
#ifdef __cplusplus
extern "C"
{
#endif


unsigned int __cdecl AddTwoNums_SDK_Func(unsigned int num1, unsigned int num2);



#ifdef __cplusplus
}
#endif
