#include "qmc1_decryption_transformer.h"
#include "qmc1_key_utils.h"

#include <memory>

namespace parakeet_crypto::transformer
{

std::unique_ptr<ITransformer> CreateQMC1StaticDecryptionTransformer(const uint8_t *key, size_t key_len)
{
    // NOLINTBEGIN(*-magic-numbers)
    if (key_len == 128)
    {
        return std::make_unique<QMC1StaticDecryptionTransformer>(key);
    }

    std::array<uint8_t, 128> key128{};
    if (key_len == 58)
    {
        qmc1::key58_to_key128(key128.data(), key);
    }
    else if (key_len == 256)
    {
        qmc1::key256_to_key128(key128.data(), key);
    }
    else
    {
        return nullptr;
    }
    return std::make_unique<QMC1StaticDecryptionTransformer>(key128.data());
    // NOLINTEND(*-magic-numbers)
}

} // namespace parakeet_crypto::transformer
