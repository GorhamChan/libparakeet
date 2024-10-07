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

////// base64 - encode

inline size_t Base64Encode(uint8_t *output, const uint8_t *input, size_t len)
{
    return base64_impl::b64_encode(output, input, len);
}
inline std::vector<uint8_t> Base64Encode(const uint8_t *input, size_t len)
{
    std::vector<uint8_t> result(base64_impl::b64_encode_buffer_len(len));
    result.resize(base64_impl::b64_encode(result.data(), input, len));
    return result;
}
template <typename T = std::vector<uint8_t>> inline std::vector<uint8_t> Base64Encode(const T &&data)
{
    return Base64Encode(reinterpret_cast<const uint8_t *>(data.data()), data.size()); // NOLINT(*-reinterpret-cast)
}
template <typename T = std::vector<uint8_t>> inline std::vector<uint8_t> Base64EncodeToString(const T &&data)
{
    std::vector<uint8_t> result(base64_impl::b64_encode_buffer_len(data.size()), '\0');
    result.resize(base64_impl::b64_encode(result.data(), data.data(), data.size()));
    return result;
}

////// base64 - decode

inline size_t Base64Decode(uint8_t *output, const uint8_t *input, size_t len)
{
    return base64_impl::b64_decode(output, input, len);
}
inline std::vector<uint8_t> Base64Decode(const uint8_t *input, size_t len)
{
    std::vector<uint8_t> result(base64_impl::b64_decode_buffer_len(len));
    result.resize(base64_impl::b64_decode(result.data(), input, len));
    return result;
}
template <typename T = std::string> inline std::vector<uint8_t> Base64Decode(const T data)
{
    return Base64Decode(reinterpret_cast<const uint8_t *>(data.data()), data.size()); // NOLINT(*-reinterpret-cast)
}
template <typename T = std::string> inline std::string Base64DecodeToString(const T data)
{
    std::string result(base64_impl::b64_decode_buffer_len(data.size()), '\0');
    // NOLINTBEGIN(*-reinterpret-cast)
    result.resize(Base64Decode(reinterpret_cast<uint8_t *>(result.data()),
                               reinterpret_cast<const uint8_t *>(data.data()), data.size()));
    // NOLINTEND(*-reinterpret-cast)
    return result;
}

} // namespace parakeet_crypto::utils
