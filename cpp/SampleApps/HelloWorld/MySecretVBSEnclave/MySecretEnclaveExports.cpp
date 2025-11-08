#include "pch.h"
#include <VbsEnclave\Enclave\Implementation\Trusted.h>

uint32_t VbsEnclave::Trusted::Implementation::DoSecretMath(_In_  std::uint32_t val1, _In_  std::uint32_t val2)
{
	return val1*val2;
}
