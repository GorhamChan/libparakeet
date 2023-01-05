#pragma once

#include <cstddef>
#include <cstdint>

#include <array>
#include <span>
#include <vector>

namespace parakeet_crypto::qmc::tea_key {

constexpr std::size_t kEncV2KeySize = 16;
using EncV2StageKey = std::span<const uint8_t, kEncV2KeySize>;
using EncV2StageKeyInput = std::span<const uint8_t, kEncV2KeySize>;

// NOLINTBEGIN(*-magic-numbers, bugprone-easily-swappable-parameters)

[[nodiscard]] std::vector<uint8_t> DecryptEncV2Key(std::span<const uint8_t> cipher,
                                                   EncV2StageKeyInput stage_1_key,
                                                   EncV2StageKeyInput stage_2_key);

[[nodiscard]] std::vector<uint8_t> EncryptEncV2Key(std::span<const uint8_t> plain,
                                                   EncV2StageKeyInput stage_1_key,
                                                   EncV2StageKeyInput stage_2_key);

// NOLINTEND(*-magic-numbers, bugprone-easily-swappable-parameters)

}  // namespace parakeet_crypto::qmc::tea_key
