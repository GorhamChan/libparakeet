#pragma once

#include "parakeet-crypto/ITransformer.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace parakeet_crypto::transformer
{

/**
 * @brief QRC Lyrics Decryption stream.
 * For json response, convert hex to bytes first.
 *
 * @param qmc1_static_transformer QMC1 static transformer
 * @param key1 Decryption key 1 (decryption order)
 * @param key2 ...
 * @param key3 ...
 * @return std::unique_ptr<ITransformer>
 */
std::unique_ptr<ITransformer> CreateQRCLyricsDecryptionTransformer(
    std::shared_ptr<ITransformer> qmc1_static_transformer, const uint8_t *key1, const uint8_t *key2,
    const uint8_t *key3);

/**
 * @brief Decrypt "music.musichallSong.PlayLyricInfo.GetPlayLyricInfo" response ("lyric", "trans", "roma")
 *
 * @param key1
 * @param key2
 * @param key3
 * @return std::vector<uint8_t>
 */
// TODO:
// std::vector<uint8_t> DecryptQRCResponse(const uint8_t *key1, const uint8_t *key2, const uint8_t *key3);

} // namespace parakeet_crypto::transformer
