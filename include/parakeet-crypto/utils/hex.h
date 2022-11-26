#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace parakeet_crypto::utils {

std::string Hex(const std::span<const uint8_t> data);
std::string HexCompactLowercase(const std::span<const uint8_t> data);

std::vector<uint8_t> UnHex(const std::span<const uint8_t> hex_str);
inline std::vector<uint8_t> UnHex(const std::string& hex_str) {
  return UnHex(std::span{reinterpret_cast<const uint8_t*>(hex_str.data()), hex_str.size()});
}
inline std::vector<uint8_t> UnHex(const std::span<const char> hex_str) {
  return UnHex(std::span{reinterpret_cast<const uint8_t*>(hex_str.data()), hex_str.size()});
}
}  // namespace parakeet_crypto::utils
