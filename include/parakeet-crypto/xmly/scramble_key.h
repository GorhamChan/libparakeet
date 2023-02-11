#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace parakeet_crypto::xmly
{

constexpr size_t kXimalayaScrambleKeyLen = 0x400;
std::vector<uint16_t> CreateScrambleKey(double mul_init, double mul_step, std::size_t n);
std::array<uint16_t, kXimalayaScrambleKeyLen> CreateScrambleKey(double mul_init, double mul_step);

} // namespace parakeet_crypto::xmly
