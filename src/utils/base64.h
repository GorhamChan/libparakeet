#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace parakeet_crypto::utils
{

std::vector<uint8_t> Base64Encode(const uint8_t *input, size_t len);
inline std::vector<uint8_t> Base64Encode(const std::vector<uint8_t> &data)
{
    return Base64Encode(data.data(), data.size());
}

std::vector<uint8_t> Base64Decode(const uint8_t *input, size_t len);
inline std::vector<uint8_t> Base64Decode(const std::string &data)
{
    return Base64Decode(reinterpret_cast<const uint8_t *>(data.data()), data.size()); // NOLINT(*-type-reinterpret-cast)
}
inline std::vector<uint8_t> Base64Decode(const std::vector<uint8_t> &data)
{
    return Base64Decode(data.data(), data.size());
}

} // namespace parakeet_crypto::utils
