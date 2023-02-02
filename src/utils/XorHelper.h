#pragma once

#include <cassert>
#include <cstddef>
#include <cstdint>

#include <algorithm>
#include <concepts>
#include <ranges>

namespace parakeet_crypto::utils
{

inline void XorFromOffset(uint8_t *dst, const uint8_t *src, size_t data_len, //
                          const uint8_t *key, size_t key_len,                //
                          size_t offset)
{
    auto *dst_end = dst + data_len;
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

inline void XorFromOffset(uint8_t *dst, size_t dst_len, const uint8_t *key, size_t key_len, size_t offset)
{
    XorFromOffset(dst, dst, dst_len, key, key_len, offset);
}

inline void XorBlockFromOffset(uint8_t *dst, const uint8_t *src, size_t data_len, size_t block_len, //
                               const uint8_t *key, size_t key_len, // NOLINT(bugprone-easily-swappable-parameters)
                               size_t offset)
{
    const auto *p_dst_end = dst + data_len;

    if (auto prev_block_offset = offset % block_len; prev_block_offset > 0)
    {
        auto process_len = std::min(data_len, block_len - prev_block_offset);
        XorFromOffset(dst, src, process_len, key, key_len, prev_block_offset);

        dst += process_len;
        src += process_len;
        data_len -= process_len;
    }

    for (const auto *p_stop = p_dst_end - block_len; dst < p_stop;)
    {
        XorFromOffset(dst, src, block_len, key, key_len, 0);

        src += block_len;
        dst += block_len;
        data_len -= block_len;
    }

    if (dst < p_dst_end)
    {
        XorFromOffset(dst, src, data_len, key, key_len, 0);
    }
}

inline void XorBlockFromOffset(uint8_t *dst, size_t data_len,      // NOLINT(bugprone-easily-swappable-parameters)
                               size_t block_len,                   //
                               const uint8_t *key, size_t key_len, // NOLINT(bugprone-easily-swappable-parameters)
                               size_t offset)
{
    XorBlockFromOffset(dst, dst, data_len, block_len, key, key_len, offset);
}
} // namespace parakeet_crypto::utils
