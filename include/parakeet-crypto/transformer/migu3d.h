#pragma once

#include "parakeet-crypto/ITransformer.h"

#include <cstdint>
#include <memory>

namespace parakeet_crypto::transformer
{

/**
 * @brief Migu3D transformer
 *
 * @param salt (32 char) fixed 32 byte string.
 * @param file_key (32 char) File key, one per file, 32 byte string.
 * @note you will need to request "/querySongBySongId.do" and look for:
 *       curl ... | jq '.resource[0].z3dCode | {androidFileKey, iosFileKey}'
 * @return std::unique_ptr<ITransformer> 
 */
std::unique_ptr<ITransformer> CreateMiguTransformer(const uint8_t* salt, const uint8_t* file_key);

/**
 * @brief Migu3D transformer (keyless)
 * 
 * @return std::unique_ptr<ITransformer> 
 */
std::unique_ptr<ITransformer> CreateKeylessMiguTransformer();

} // namespace parakeet_crypto::transformer
