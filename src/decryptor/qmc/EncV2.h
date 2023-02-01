#pragma once

#include <cstddef>
#include <cstdint>

#include <array>
#include <span>
#include <vector>

namespace parakeet_crypto::qmc::tea_key
{

constexpr std::size_t kEncV2KeySize = 16;

// NOLINTBEGIN(*-magic-numbers, bugprone-easily-swappable-parameters)

[[nodiscard]] std::vector<uint8_t> DecryptEncV2Key(const uint8_t *cipher, size_t cipher_len, const uint8_t *stage_1_key,
                                                   const uint8_t *stage_2_key);

[[nodiscard]] std::vector<uint8_t> EncryptEncV2Key(const uint8_t *plain, size_t plain_len, const uint8_t *stage_1_key,
                                                   const uint8_t *stage_2_key);

// NOLINTEND(*-magic-numbers, bugprone-easily-swappable-parameters)

} // namespace parakeet_crypto::qmc::tea_key
