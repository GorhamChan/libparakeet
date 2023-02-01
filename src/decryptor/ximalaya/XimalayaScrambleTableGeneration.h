#pragma once

#include <cstdint>

#include <span>

namespace parakeet_crypto::decryptor::ximalaya
{

void GenerateScrambleTable(std::span<uint16_t> result, double mul_init, double mul_step);

} // namespace parakeet_crypto::decryptor::ximalaya
