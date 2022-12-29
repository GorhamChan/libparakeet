#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace parakeet_crypto::decryptor::ximalaya {

std::vector<uint16_t> generate_ximalaya_scramble_table(double mul_init, double mul_step, std::size_t n);

}  // namespace parakeet_crypto::decryptor::ximalaya
