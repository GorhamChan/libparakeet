#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace parakeet_crypto::utils
{

namespace base64_impl
{

/**
 * Get buffer size to encode base64 string
 */
inline size_t b64_encode_buffer_len(size_t len)
{
    // Every 3 bytes input, it will yield 4 bytes (chars) base64-encoded string
    // +1 for the null terminator
    return (len + 2) / 3 * 4 + 1;
}

inline size_t b64_decode_buffer_len(size_t len)
{
    // Every 4 bytes in, it will yield 3 bytes output
    return (len + 3) / 4 * 3;
}

size_t b64_encode(uint8_t *output, const uint8_t *input, size_t input_len);
size_t b64_decode(uint8_t *output, const uint8_t *input, size_t input_len);

} // namespace base64_impl

std::vector<uint8_t> Base64Encode(const uint8_t *input, size_t len);
inline std::vector<uint8_t> Base64Encode(const std::vector<uint8_t> &data)
{
    return Base64Encode(data.data(), data.size());
}
inline std::vector<uint8_t> Base64Encode(const std::string &data)
{
    return Base64Encode(reinterpret_cast<const uint8_t *>(data.c_str()), data.size()); // NOLINT(*-reinterpret-cast)
}

std::vector<uint8_t> Base64Decode(const uint8_t *input, size_t len);
inline std::vector<uint8_t> Base64Decode(const std::string &data)
{
    return Base64Decode(reinterpret_cast<const uint8_t *>(data.data()), data.size()); // NOLINT(*-reinterpret-cast)
}
inline std::vector<uint8_t> Base64Decode(const std::vector<uint8_t> &data)
{
    return Base64Decode(data.data(), data.size());
}

} // namespace parakeet_crypto::utils
