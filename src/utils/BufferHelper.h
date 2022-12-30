#pragma once

#include <cstdint>

#include <algorithm>
#include <span>
#include <vector>

namespace parakeet_crypto::utils {

template <typename T>
inline bool BufferEqual(std::span<const T> src1, std::span<const T> src2) {
    return src1.size() == src2.size() && std::equal(src1.begin(), src1.end(), src2.begin());
}

template <typename T>
inline bool BufferStartsWith(std::span<const T> src, std::span<const T> prefix) {
    return src.size() >= prefix.size() && std::equal(prefix.begin(), prefix.end());
}

}  // namespace parakeet_crypto::utils
