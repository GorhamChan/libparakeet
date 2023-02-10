#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <optional>
#include <vector>

namespace parakeet_crypto::qmc2_map
{

constexpr size_t kIndexOffset = 71214;

// NOLINTBEGIN(*-magic-numbers)

inline void to_key128(uint8_t *key128, const uint8_t *key_blob, size_t key_len)
{
    if (key_len == 0)
    {
        std::fill_n(key128, 128, 0xcc);
        return;
    }

    std::vector<uint8_t> long_key(key_len, 0);

    uint8_t shift_counter = 4;
    for (auto &key : long_key)
    {
        uint8_t value = *key_blob++;
        key = (value << shift_counter) | (value >> shift_counter);
        shift_counter = (shift_counter + 1) & 0b0111;
    }

    for (size_t i = 0; i < 128; i++)
    {
        key128[i] = long_key[(static_cast<size_t>(i * i) + kIndexOffset) % key_len];
    }
}

// NOLINTEND(*-magic-numbers)

} // namespace parakeet_crypto::qmc2_map
