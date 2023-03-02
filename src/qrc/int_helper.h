#pragma once
#include "qrc/qrc_des_data.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <numeric>

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

inline uint64_t constexpr get_u64_by_shift_idx(uint8_t shift_idx)
{
    return uint64_t{1} << (31 - shift_idx);
}

inline uint32_t constexpr map_bit_u64_to_u32(uint64_t data, uint8_t check_idx, uint8_t set_bit_idx)
{
    uint64_t check_mask = get_u64_by_shift_idx(check_idx);
    if ((data & check_mask) != uint64_t{0})
    {
        return get_u64_by_shift_idx(set_bit_idx);
    }

    return 0;
}

inline uint32_t constexpr map_bit_u32(uint32_t data, uint8_t check_idx, uint8_t set_bit_idx)
{
    return map_bit_u64_to_u32(static_cast<uint64_t>(data), check_idx, set_bit_idx);
}

template <size_t N> inline uint32_t constexpr map_u32_bits(uint32_t src_value, const std::array<uint8_t, N> &table)
{
    static_assert(N <= 32, "table is too big to fit inside u32");

    int i = 0;
    return std::accumulate(table.cbegin(), table.cend(), uint32_t{0}, [&](uint32_t result, const auto &check_idx) {
        return result | map_bit_u32(src_value, check_idx, i++);
    });
}

template <size_t N>
inline uint64_t constexpr map_2_u32_bits_to_u64(uint32_t src_lo32, const std::array<uint8_t, N> &table_lo32,
                                                uint32_t src_hi32, const std::array<uint8_t, N> &table_hi32)
{
    uint64_t result{0};
    auto lo32_it = table_lo32.cbegin();
    auto hi32_it = table_hi32.cbegin();
    for (int i = 0; i < N; i++)
    {
        auto temp_lo32 = map_bit_u32(src_lo32, *lo32_it++, i);
        result |= uint64_t{temp_lo32};

        auto temp_hi32 = map_bit_u32(src_hi32, *hi32_it++, i);
        result |= uint64_t{temp_hi32} << 32;
    }

    return result;
}

template <typename It>
inline constexpr uint32_t map_u64_to_u32_bits(uint64_t src_value, const It &&begin, const It &&end)
{
    int i = 0;
    return std::accumulate(begin, end, uint32_t{0}, [&](uint32_t result, const auto &check_idx) {
        return result | map_bit_u64_to_u32(src_value, check_idx, i++);
    });
}

template <size_t N>
inline constexpr uint32_t map_u64_to_u32_bits(uint64_t src_value, const std::array<uint8_t, N> &table)
{
    static_assert(N <= 32, "table is too big to fit inside u32");

    return map_u64_to_u32_bits(src_value, table.cbegin(), table.cend());
}

inline constexpr uint64_t map_u64_bits(uint64_t value, const std::array<uint8_t, 64> &table)
{
    uint32_t lo32 = map_u64_to_u32_bits(value, table.cbegin(), table.cbegin() + 32);
    uint32_t hi32 = map_u64_to_u32_bits(value, table.cbegin() + 32, table.cend());
    return make_u64(hi32, lo32);
}

// NOLINTEND (*-magic-numbers)

} // namespace parakeet_crypto::qrc::int_helper
