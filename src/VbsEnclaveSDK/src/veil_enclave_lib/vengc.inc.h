#include "..\veil_enclave_lib\vengcdll.h"

#include <winenclave.h>
#include <winenclaveapi.h>
#include <ncrypt.h>
#include <sal.h>
#include <bcrypt.h>
#include <stddef.h>
#include <new>
//#include <iumtypes.h>
#include <ntenclv.h>
#include "vtl1mutualauth.nostd.h"
#include <veinterop_kcm.h>
#include "wil_raw.h"
#include "memory.h"

#define TRUSTLETIDENTITY_NGC 6
