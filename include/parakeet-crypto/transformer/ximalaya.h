#pragma once

#include "parakeet-crypto/ITransformer.h"

#include <cstdint>
#include <memory>

namespace parakeet_crypto::transformer
{

constexpr size_t kXimalayaScrambleKeyLen = 0x400;
std::unique_ptr<ITransformer> CreateXimalayaDecryptionTransformer(const uint16_t *scramble_key,
                                                                  const uint8_t *content_key, size_t content_key_len);

} // namespace parakeet_crypto::transformer
