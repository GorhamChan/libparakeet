#pragma once

#include <cstddef>

#include <algorithm>
#include <concepts>
#include <ranges>
#include <span>

namespace parakeet_crypto::utils {

template <std::size_t KEY_SIZE, std::unsigned_integral T, typename S1, typename S2>
    requires(KEY_SIZE % 4 == 0) && std::is_same_v<uint8_t, typename std::remove_const_t<S1>> &&
            std::is_same_v<uint8_t, typename std::remove_const_t<S2>>
inline void XorBlockWithOffset(std::span<uint8_t> dest, std::span<S1> src, std::span<S2, KEY_SIZE> key, T offset) {
    if (offset % KEY_SIZE != 0) {
        auto src_offset = offset % KEY_SIZE;
        auto len = KEY_SIZE - offset % KEY_SIZE;
        std::ranges::transform(src.begin(), src.begin() + len, key.begin() + src_offset, key.end(), dest.begin(),
                               [](const auto& v1, const auto& v2) { return v1 ^ v2; });

        dest = std::span{dest.begin() + len, dest.size() - len};
        src = std::span{src.begin() + len, src.size() - len};
    }

    // Process in blocks, that can be optimised by compiler.
    std::size_t len_in_block = dest.size() - dest.size() % KEY_SIZE;
    for (std::size_t i = 0; i < len_in_block; i += KEY_SIZE)
        for (std::size_t j = 0; j < KEY_SIZE; j++)
            dest[i + j] ^= key[j];

    dest = std::span{dest.begin() + len_in_block, dest.size() - len_in_block};
    src = std::span{src.begin() + len_in_block, src.size() - len_in_block};
    std::ranges::transform(src, key, dest.begin(), [](const auto& v1, const auto& v2) { return v1 ^ v2; });
}

template <std::size_t KEY_SIZE, std::unsigned_integral T, typename S1>
    requires(KEY_SIZE % 4 == 0) && std::is_same_v<uint8_t, typename std::remove_const_t<S1>>
inline void XorBlockWithOffset(std::span<uint8_t> dst, std::span<S1, KEY_SIZE> src, T offset) {
    XorBlockWithOffset(dst, dst, src, offset);
}

}  // namespace parakeet_crypto::utils
