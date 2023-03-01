#pragma once
#include "qrc/qrc_des_data.h"

#include <array>
#include <cstddef>
#include <cstdint>

namespace parakeet_crypto::qrc::int_helper
{

// NOLINTBEGIN (*-magic-numbers)
inline constexpr uint64_t make_u64(uint32_t hi32, uint32_t lo32)
{
    return (uint64_t{hi32} << 32) | uint64_t{lo32}; // NOLINT (*-magic-numbers)
}

inline constexpr uint64_t swap_u64_side(uint64_t value)
{
    return (value << 32) | (value >> 32); // NOLINT (*-magic-numbers)
}

inline constexpr uint32_t u64_get_lo32(uint64_t value)
{
    return static_cast<uint32_t>(value);
}

inline constexpr uint32_t u64_get_hi32(uint64_t value)
{
    return static_cast<uint32_t>(value >> 32U);
}

inline uint32_t constexpr map_bit_u64_to_u32(uint64_t data, uint8_t check_idx, uint8_t set_bit_idx)
{
    uint64_t check_mask = data::des_u64_shift_table[check_idx];
    if ((data & check_mask) != 0U)
    {
        return data::des_u64_shift_table[set_bit_idx];
    }

    return 0;
}

inline uint32_t constexpr map_bit_u32(uint32_t data, uint8_t check_idx, uint8_t set_bit_idx)
{
    return map_bit_u64_to_u32(static_cast<uint64_t>(data), check_idx, set_bit_idx);
}

template <size_t N>
inline uint32_t constexpr map_u32_bits(uint32_t value, const std::array<uint8_t, N> &table, int delta = -1)
{
    static_assert(N <= 32, "table is too big to fit inside u32");

    uint32_t result{0};
    for (int i = 0; i < N; i++)
    {
        result |= map_bit_u32(value, table[i] + delta, i);
    }

    return result;
}

template <size_t N>
inline constexpr uint32_t map_u64_to_u32_bits(uint64_t value, const std::array<uint8_t, N> &table, int delta = -1)
{
    static_assert(N <= 32, "table is too big to fit inside u32");

    uint32_t result{0};
    for (int i = 0; i < N; i++)
    {
        result |= map_bit_u64_to_u32(value, table[i] + delta, i);
    }

    return result;
}

inline constexpr uint64_t map_u64_bits(uint64_t value, const std::array<uint8_t, 64> &table, int delta = -1)
{
    uint64_t result{0};
    for (int i = 0; i < 32; i++)
    {
        uint32_t lo32 = map_bit_u64_to_u32(value, table[i] + delta, i);
        uint32_t hi32 = map_bit_u64_to_u32(value, table[i + 32] + delta, i);
        result |= make_u64(hi32, lo32);
    }

    return result;
}

// NOLINTEND (*-magic-numbers)

} // namespace parakeet_crypto::qrc::int_helper
