#pragma once

#include "parakeet-crypto/decryptor/StreamDecryptor.h"

#include <array>
#include <memory>
#include <span>

namespace parakeet_crypto::decryptor {

namespace ximalaya {

constexpr std::size_t kX2MContentKeySize = 0x04;
constexpr std::size_t kX3MContentKeySize = 0x20;
constexpr std::size_t kXmlyScrambleTableSize = 0x400;

using X2MContentKey = std::array<uint8_t, kX2MContentKeySize>;
using X3MContentKey = std::array<uint8_t, kX3MContentKeySize>;
using ScrambleTable = std::array<uint16_t, kXmlyScrambleTableSize>;

}  // namespace ximalaya

/**
 * @brief Create a Ximalaya X2M / X3M decryptor.
 *
 * @param content_key Content key, which can have a size of 4 or 32.
 * @param init_value Scramble table generation parameter.
 * @param step_value Scramble table generation parameter.
 * @return std::unique_ptr<StreamDecryptor>
 */
std::unique_ptr<StreamDecryptor> CreateXimalayaDecryptor(std::span<const uint8_t> content_key,
                                                         double init_value,
                                                         double step_value);

std::unique_ptr<StreamDecryptor> CreateXimalayaDecryptor(
    std::span<const uint8_t> content_key,
    std::span<const uint16_t, ximalaya::kXmlyScrambleTableSize> scramble_table);

}  // namespace parakeet_crypto::decryptor
