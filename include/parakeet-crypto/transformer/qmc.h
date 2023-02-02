#pragma once

#include "parakeet-crypto/ITransformer.h"

#include <cstddef>
#include <cstdint>
#include <memory>

namespace parakeet_crypto::transformer
{

std::unique_ptr<ITransformer> CreateQMC1StaticDecryptionTransformer(const uint8_t *key, size_t key_len);
// std::unique_ptr<ITransformer> CreateQMC2MapDecryptionTransformer(const uint8_t *key);

namespace QMC1
{

} // namespace QMC1

} // namespace parakeet_crypto::transformer
