#include "qmc1_decryption_transformer.h"
#include "qmc2_map_key_utils.h"
#include "transformer/qmc/qmc2_map_key_utils.h"

#include <memory>

namespace parakeet_crypto::transformer
{

std::unique_ptr<ITransformer> CreateQMC2MapDecryptionTransformer(const uint8_t *key, size_t key_len)
{
    std::array<uint8_t, 128> key128{}; // NOLINT(*-magic-numbers)
    qmc2_map::to_key128(key128.data(), key, key_len);
    return std::make_unique<QMC1StaticDecryptionTransformer<qmc2_map::kIndexOffset>>(key128.data());
}

} // namespace parakeet_crypto::transformer
