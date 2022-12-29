#include "utils/md5.h"

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>
#include <span>

namespace parakeet_crypto::utils {

std::array<uint8_t, MD5_DIGEST_SIZE> md5(const std::span<const uint8_t> data) {
  std::array<uint8_t, MD5_DIGEST_SIZE> digest;

  CryptoPP::Weak::MD5 hash;
  hash.Update(data.data(), data.size());
  hash.Final(&digest[0]);

  return digest;
}

}  // namespace parakeet_crypto::utils
