#pragma once

#include <cstddef>
#include <cstdint>

namespace parakeet_crypto::qmc1
{

constexpr size_t kIndexOffset = 80923 % 256;

// NOLINTBEGIN(*-magic-numbers)

inline void key58_to_key128(uint8_t *key128, const uint8_t *key58)
{
    constexpr size_t kIterCount = 64 / 16;
    auto *p_key128 = key128;
    const auto *p_key58 = key58 + 2;

    auto copy_row = [&](uint8_t header, int delta) {
        *p_key128++ = header;
        for (int i = 0; i < 7; i++)
        {
            *p_key128++ = *p_key58;
            p_key58 += delta;
        }
    };

    auto copy_block = [&](int delta) {
        for (int i = 0; i < 128 / 2 / 16; i++)
        {
            copy_row(key58[0], delta);
            copy_row(key58[1], delta);
        }
    };

    copy_block(+1);
    p_key58--;
    copy_block(-1);
}

inline void key128_normalize(uint8_t *key128)
{
    // Noop
}

inline void key256_to_key128(uint8_t *key128, const uint8_t *key256)
{
    for (int i = 0; i < 128; i++)
    {
        key128[i] = key256[(static_cast<uint32_t>(i * i) + kIndexOffset) % 256];
    }
}

// NOLINTEND(*-magic-numbers)

} // namespace parakeet_crypto::qmc1
