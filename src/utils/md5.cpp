#include "utils/md5.h"

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>

namespace parakeet_crypto::utils
{

std::array<uint8_t, MD5_DIGEST_SIZE> md5(const uint8_t *data, size_t len)
{
    std::array<uint8_t, MD5_DIGEST_SIZE> digest{};

    CryptoPP::Weak::MD5 hash;
    hash.Update(data, len);
    hash.Final(digest.data());

    return digest;
}

} // namespace parakeet_crypto::utils
