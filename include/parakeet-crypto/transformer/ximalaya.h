#pragma once

#include "parakeet-crypto/ITransformer.h"
#include "parakeet-crypto/xmly/scramble_key.h"

#include <cassert>
#include <cstdint>
#include <memory>

namespace parakeet_crypto::transformer
{

constexpr size_t kXimalayaScrambleKeyLen = xmly::kXimalayaScrambleKeyLen;
std::unique_ptr<ITransformer> CreateXimalayaDecryptionTransformer(const uint16_t *scramble_key,
                                                                  const uint8_t *content_key, size_t content_key_len);

template <typename ScrambleKeyContainer, typename ContentKeyContainer>
inline std::unique_ptr<ITransformer> CreateXimalayaDecryptionTransformer(ScrambleKeyContainer scramble_key,
                                                                         ContentKeyContainer content_key)
{
    assert(("scramble key size mismatch", scramble_key.size() == kXimalayaScrambleKeyLen));
    return CreateXimalayaDecryptionTransformer(scramble_key.data(), content_key.data(), content_key.size());
}

} // namespace parakeet_crypto::transformer
