#pragma once

#include <cassert>
#include <cstddef>
#include <cstdint>

#include <algorithm>
#include <concepts>
#include <ranges>

namespace parakeet_crypto::utils
{

inline void XorBlockWithOffset(uint8_t *dst, const uint8_t *src, size_t xor_len, const uint8_t *key, size_t key_len,
                               size_t offset)
{
    auto *dst_end = dst + xor_len;
    auto *dst_end_last_block = dst_end - key_len;

    if (offset % key_len != 0)
    {
        auto block_offset = offset % key_len;
        const auto *stc_stop = &dst[block_offset];
        const auto *p_key = &key[block_offset];
        while (dst < stc_stop)
        {
            *dst++ = *src++ ^ *p_key++;
        }
    }

    // Process in blocks, that can be optimised by compiler.
    while (dst < dst_end_last_block)
    {
        for (auto i = 0; i < key_len; i++)
        {
            *dst++ = *src++ ^ key[i];
        }
    }

    while (dst < dst_end)
    {
        *dst++ = *src++ ^ *key++;
    }
}

inline void XorBlockWithOffset(uint8_t *dst, size_t dst_len, const uint8_t *key, size_t key_len, size_t offset)
{
    XorBlockWithOffset(dst, dst, dst_len, key, key_len, offset);
}

} // namespace parakeet_crypto::utils
