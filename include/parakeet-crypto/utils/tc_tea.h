#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>

namespace parakeet_crypto::utils
{

// Exported from "tc_tea" for convience.

std::vector<uint8_t> TeaEncrypt(const uint8_t *data, size_t data_len, const uint8_t *key);
std::vector<uint8_t> TeaDecrypt(const uint8_t *data, size_t data_len, const uint8_t *key);

} // namespace parakeet_crypto::utils
