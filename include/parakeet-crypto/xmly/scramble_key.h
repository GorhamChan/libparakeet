#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace parakeet_crypto::xmly
{

std::vector<uint16_t> CreateScrambleKey(double mul_init, double mul_step, std::size_t n);

} // namespace parakeet_crypto::xmly
