#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace parakeet_crypto::utils {

std::string Hex(const std::span<const uint8_t> v);
std::string HexCompactLowercase(const std::span<const uint8_t> data);
std::vector<uint8_t> UnHex(const std::string& v);

}  // namespace parakeet_crypto::utils
