#pragma once

#include <array>

#include <cstddef>
#include <cstdint>

namespace parakeet_crypto::utils {

constexpr std::size_t MD5_DIGEST_SIZE = 16;

std::array<uint8_t, MD5_DIGEST_SIZE> md5(const uint8_t* data, size_t len);

}  // namespace parakeet_crypto::utils
