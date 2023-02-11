#pragma once

#include "parakeet-crypto/ITransformer.h"

#include <cstdint>
#include <memory>

namespace parakeet_crypto::transformer
{

constexpr size_t kKuwoDecryptionKeySize = 0x20;
std::unique_ptr<ITransformer> CreateKuwoDecryptionTransformer(const uint8_t *key);
std::unique_ptr<ITransformer> CreateKuwoEncryptionTransformer(const uint8_t *key, uint64_t resource_id);

} // namespace parakeet_crypto::transformer