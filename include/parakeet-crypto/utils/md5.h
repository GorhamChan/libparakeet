#pragma once

#include <array>
#include <cstdint>
#include <span>

namespace parakeet_crypto::utils {

std::array<uint8_t, 16> md5(const std::span<const uint8_t> data);

}
