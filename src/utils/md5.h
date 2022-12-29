#pragma once

#include <array>
#include <cstdint>
#include <span>

namespace parakeet_crypto::utils {

constexpr std::size_t MD5_DIGEST_SIZE = 16;

std::array<uint8_t, MD5_DIGEST_SIZE> md5(const std::span<const uint8_t> data);

}  // namespace parakeet_crypto::utils
