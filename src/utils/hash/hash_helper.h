#pragma once

#include "utils/endian_helper.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <utility>

namespace parakeet_crypto::utils::hash
{

inline uint32_t rol_u32(uint32_t value, uint32_t bits)
{
    constexpr uint32_t kBitsU32 = 32;
    return (value << bits) | (value >> (kBitsU32 - (bits)));
}

// Copy state to digest.
template <bool BigEndian> inline void state_to_digest(uint8_t *digest, uint32_t *state, size_t n_state_count)
{
    // Write digest
    auto *p_digest = &digest[0];
    for (size_t i = 0; i < n_state_count; i++, p_digest += sizeof(state[0]))
    {
        if constexpr (BigEndian)
        {
            WriteBigEndian(p_digest, state[i]);
        }
        else
        {
            WriteLittleEndian(p_digest, state[i]);
        }
    }
}

template <size_t BLOCK_SIZE, bool BigEndian>
inline std::pair<std::array<uint8_t, BLOCK_SIZE + sizeof(uint64_t)>, size_t> //
prepare_md_final_block(uint64_t count)
{
    constexpr uint8_t kEndOfDataMark = 0x80;
    constexpr uint8_t kBitsPerByte = 8;

    // padding begin mark + padding{ size = [0, BLOCK_SIZE) } + uint64_t{data_byte_count}
    std::array<uint8_t, BLOCK_SIZE + sizeof(uint64_t)> padding{kEndOfDataMark};

    size_t pad_size = 1;
    auto offset = count % BLOCK_SIZE;
    auto expected_offset = BLOCK_SIZE - sizeof(uint64_t) - 1;
    if (offset != expected_offset)
    {
        pad_size += (expected_offset + BLOCK_SIZE - offset) % BLOCK_SIZE;
    }

    if constexpr (BigEndian)
    {
        WriteBigEndian(&padding.at(pad_size), count * kBitsPerByte);
    }
    else
    {
        WriteLittleEndian(&padding.at(pad_size), count * kBitsPerByte);
    }
    return std::make_pair(padding, pad_size + sizeof(uint64_t));
}

} // namespace parakeet_crypto::utils::hash