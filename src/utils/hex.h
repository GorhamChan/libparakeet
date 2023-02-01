#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace parakeet_crypto::utils
{

std::string Hex(const uint8_t *data, size_t len, bool upper = true, bool add_space = true);

std::vector<uint8_t> UnHex(const uint8_t *hex_str, size_t len);

inline std::vector<uint8_t> UnHex(const std::string &hex_str)
{
    return UnHex(reinterpret_cast<const uint8_t *>(hex_str.data()), hex_str.size()); // NOLINT(*-type-reinterpret-cast)
}
inline std::vector<uint8_t> UnHex(const char *hex_str, size_t len)
{
    return UnHex(reinterpret_cast<const uint8_t *>(hex_str), len); // NOLINT(*-type-reinterpret-cast)
}
} // namespace parakeet_crypto::utils
