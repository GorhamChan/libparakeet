#pragma once

#include "parakeet-crypto/ITransformer.h"
#include "parakeet-crypto/qmc2/footer_parser.h"

#include <cstddef>
#include <cstdint>
#include <memory>

namespace parakeet_crypto::transformer
{

std::unique_ptr<ITransformer> CreateQMC1StaticDecryptionTransformer(const uint8_t *key, size_t key_len);

std::unique_ptr<ITransformer> CreateQMC2MapDecryptionTransformer(const uint8_t *key, size_t key_len);
std::unique_ptr<ITransformer> CreateQMC2RC4DecryptionTransformer(const uint8_t *key, size_t key_len);

/**
 * @brief Transformer wrapper that will run the stream through `CreateQMC2MapDecryptionTransformer`
 *        or `CreateQMC2RC4DecryptionTransformer` depending on the key size it has parsed.
 *
 * @param footer_parser
 * @return std::unique_ptr<ITransformer>
 */
std::unique_ptr<ITransformer> CreateQMC2DecryptionTransformer(std::shared_ptr<qmc2::QMCFooterParser> footer_parser);

// Make API a bit easier to consume...

template <typename Container> inline std::unique_ptr<ITransformer> CreateQMC1StaticDecryptionTransformer(Container key)
{
    return CreateQMC1StaticDecryptionTransformer(key.data(), key.size());
}
template <typename Container> inline std::unique_ptr<ITransformer> CreateQMC2MapDecryptionTransformer(Container key)
{
    return CreateQMC2MapDecryptionTransformer(key.data(), key.size());
}
template <typename Container> inline std::unique_ptr<ITransformer> CreateQMC2RC4DecryptionTransformer(Container key)
{
    return CreateQMC2RC4DecryptionTransformer(key.data(), key.size());
}

} // namespace parakeet_crypto::transformer
