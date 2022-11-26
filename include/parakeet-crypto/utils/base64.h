#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace parakeet_crypto::utils {

std::string Base64Encode(const std::span<const uint8_t> input);
inline std::vector<uint8_t> Base64EncodeBytes(const std::span<const uint8_t> data) {
  auto result_str = Base64Encode(data);
  return std::vector<uint8_t>(result_str.begin(), result_str.end());
}

std::vector<uint8_t> Base64Decode(const std::span<const uint8_t> input);
inline std::vector<uint8_t> Base64Decode(const std::span<const char> input) {
  return Base64Decode(std::span{reinterpret_cast<const uint8_t*>(input.data()), input.size()});
}

}  // namespace parakeet_crypto::utils
