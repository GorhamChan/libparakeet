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
    if constexpr (sizeof(void *) == 8)
    {
        return uint64_t{1} << (31 - shift_idx);
    }

    // 32-bit: use table lookup instead for performance
    return data::kU64ShiftTable[shift_idx % data::kU64ShiftTable.size()];
}

template <typename T> inline void constexpr map_bit(T &result, uint64_t src, uint8_t check, uint8_t set)
{
    uint64_t check_mask = get_u64_by_shift_idx(check);
    if ((src & check_mask) != uint64_t{0})
    {
        result |= get_u64_by_shift_idx(set);
    }
}

template <size_t N> inline uint32_t constexpr map_u32_bits(uint32_t src_value, const std::array<uint8_t, N> &table)
{
    static_assert(N <= 32, "table is too big to fit inside u32");

    int i = 0;
    return std::accumulate(table.cbegin(), table.cend(), uint32_t{0}, [&](uint32_t result, const auto &check_idx) {
        map_bit(result, src_value, check_idx, i++);
        return result;
    });
}

template <size_t N> inline uint64_t constexpr map_u64(uint64_t src_value, const std::array<uint8_t, N> &table)
{
    static_assert(N % 2 == 0, "N should be even");
    constexpr size_t N_MID = N / 2;

    auto lo32_it = table.cbegin();
    uint32_t lo32{0};

    auto hi32_it = table.cbegin() + N_MID;
    uint32_t hi32{0};

    for (int i = 0; i < N_MID; i++)
    {
        map_bit(lo32, src_value, *lo32_it++, i);
        map_bit(hi32, src_value, *hi32_it++, i);
    }

    return make_u64(hi32, lo32);
}

// NOLINTEND (*-magic-numbers)

} // namespace parakeet_crypto::qrc::int_helper
