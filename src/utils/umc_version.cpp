
#if __has_include("parakeet-crypto/constants.build_time.h")
#include "parakeet-crypto/constants.build_time.h"
#endif

#ifndef UM_CRYPTO_VERSION
#define UM_CRYPTO_VERSION "unknown"
#endif

const char* const umc_version = UM_CRYPTO_VERSION;
