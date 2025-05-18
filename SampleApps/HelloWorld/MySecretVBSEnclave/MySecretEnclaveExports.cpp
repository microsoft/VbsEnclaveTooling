//#include "pch.h"

//#include <array>
//#include <stdexcept>
//
//#include <veil\enclave\crypto.vtl1.h>
//#include <veil\enclave\logger.vtl1.h>
//#include <veil\enclave\taskpool.vtl1.h>
//#include <veil\enclave\vtl0_functions.vtl1.h>

#include <VbsEnclave\Enclave\Implementations.h>

uint32_t VbsEnclave::VTL1_Declarations::DoSecretMath(_In_  std::uint32_t val1, _In_  std::uint32_t val2)
{
	return val1*val2;
}