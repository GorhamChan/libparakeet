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
template <typename T = std::vector<uint8_t>> inline std::vector<uint8_t> Base64Encode(const T &&data)
{
    return Base64Encode(reinterpret_cast<const uint8_t *>(data.data()), data.size()); // NOLINT(*-reinterpret-cast)
}

std::vector<uint8_t> Base64Decode(const uint8_t *input, size_t len);
template <typename T = std::string> inline std::vector<uint8_t> Base64Decode(const T &&data)
{
    return Base64Decode(reinterpret_cast<const uint8_t *>(data.data()), data.size()); // NOLINT(*-reinterpret-cast)
}

} // namespace parakeet_crypto::utils
