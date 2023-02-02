#pragma once

#include "utils/RotateArray.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

namespace parakeet_crypto::qmc2_map
{

constexpr size_t kIndexOffset = 71214;

// NOLINTBEGIN(*-magic-numbers)

inline void key128_normalize(uint8_t *key128)
{
    utils::RotateLeft<128, kIndexOffset>(key128);
}

inline void key256_to_key128(uint8_t *key128, const uint8_t *key256)
{
    std::array<uint8_t, 256> key256_local{};

    uint8_t shift_counter = 4;
    for (auto &key : key256_local)
    {
        uint8_t value = *key256++;
        key = (value << shift_counter) | (value >> shift_counter);
        shift_counter = (shift_counter + 1) & 0b0111;
    }

    utils::RotateLeft<256, kIndexOffset>(key256_local.data());

    for (int i = 0; i < 128; i++)
    {
        key128[i] = key256_local[(static_cast<uint32_t>(i * i) + kIndexOffset) % 256];
    }
}

// NOLINTEND(*-magic-numbers)

} // namespace parakeet_crypto::qmc2_map
