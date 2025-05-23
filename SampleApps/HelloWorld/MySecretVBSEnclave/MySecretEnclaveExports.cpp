#include "pch.h"
#include <VbsEnclave\Enclave\Implementations.h>

uint32_t VbsEnclave::VTL1_Declarations::DoSecretMath(_In_  std::uint32_t val1, _In_  std::uint32_t val2)
{
	return val1*val2;
}
