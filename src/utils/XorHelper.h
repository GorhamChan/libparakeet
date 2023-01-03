#pragma once

#include <cassert>
#include <cstddef>

#include <algorithm>
#include <concepts>
#include <ranges>
#include <span>

namespace parakeet_crypto::utils {

template <typename T>
concept U8Input = std::is_same_v<uint8_t, typename std::remove_const_t<T>>;

template <std::size_t KEY_SIZE, std::unsigned_integral T, U8Input S1, U8Input S2>
    requires(KEY_SIZE >= 8)
inline void XorBlockWithOffset(std::span<uint8_t> dest, std::span<S1> src, std::span<S2, KEY_SIZE> key, T offset) {
    assert(("key size should match; did you forgot to cast the key?", key.size() == KEY_SIZE));
    assert(("src/dest size should match", dest.size() == src.size()));

    if (offset % KEY_SIZE != 0) {
        auto src_offset = offset % KEY_SIZE;
        auto len = KEY_SIZE - offset % KEY_SIZE;
        std::ranges::transform(src.begin(), src.begin() + len, key.begin() + src_offset, key.end(), dest.begin(),
                               [](const auto& v1, const auto& v2) { return v1 ^ v2; });

        dest = dest.subspan(len);
        src = src.subspan(len);
    }

    // Process in blocks, that can be optimised by compiler.
    std::size_t len_in_block = dest.size() - dest.size() % KEY_SIZE;
    for (std::size_t i = 0; i < len_in_block; i += KEY_SIZE)
        for (std::size_t j = 0; j < KEY_SIZE; j++)
            dest[i + j] = src[i + j] ^ key[j];

    dest = dest.subspan(len_in_block);
    src = src.subspan(len_in_block);
    std::ranges::transform(src, key, dest.begin(), [](const auto& v1, const auto& v2) { return v1 ^ v2; });
}

template <std::size_t KEY_SIZE, std::unsigned_integral T, U8Input S1, U8Input S2>
inline void XorBlockWithOffset(std::span<uint8_t> dest, std::span<S1> src, std::span<S2> key, T offset) {
    assert(("src/dest size should match", dest.size() == src.size()));
    assert(("key should not be empty", !key.empty()));

    auto data_size = dest.size();
    auto key_size = key.size();
    auto key_offset = offset;

    for (std::size_t i = 0; i < data_size; i++, key_offset++) {
        dest[i] = src[i] ^ key[key_offset % key.size()];
    }
}

template <std::size_t KEY_SIZE, std::unsigned_integral T, U8Input S1>
inline void XorBlockWithOffset(std::span<uint8_t> dst, std::span<S1, KEY_SIZE> src, T offset) {
    XorBlockWithOffset(dst, dst, src, offset);
}

}  // namespace parakeet_crypto::utils
