#pragma once

#include <cstddef>
#include <cstdint>

namespace parakeet_crypto::utils
{

template <size_t const BLOCK_SIZE> inline int PKCS7_unpad(const uint8_t *data, size_t data_len, size_t &new_len)
{
    new_len = 0;

    if (data_len == 0)
    {
        return 1; // buff too small
    }

    uint8_t trim = data[data_len - 1];
    if (trim == 0 || static_cast<size_t>(trim) >= data_len)
    {
        return 2; // Invalid padding length
    }

    if constexpr (BLOCK_SIZE != 0)
    {
        if (static_cast<size_t>(trim) > BLOCK_SIZE)
        {
            return 3; // padding larger than block size
        }
    }

    size_t unpadded_len = data_len - trim;
    uint8_t pad_verify{0}; // expect to be zero
    const uint8_t *ptr = &data[unpadded_len];
    const uint8_t *end = &data[data_len];
    while (ptr < end)
    {
        pad_verify |= *ptr++ ^ trim;
    }

    if (pad_verify != 0)
    {
        return 4; // some padding bytes mismatch
    }

    new_len = unpadded_len;
    return 0;
}

template <size_t const BLOCK_SIZE, typename Container> inline bool PKCS7_unpad(Container &&data)
{
    size_t unpadded_len{0};
    if (PKCS7_unpad<BLOCK_SIZE>(data.data(), data.size(), unpadded_len) == 0)
    {
        data.resize(unpadded_len, 0);
        return true;
    }

    return false;
}

template <size_t const BLOCK_SIZE> inline bool PKCS7_pad()
{
    static_assert(BLOCK_SIZE != 0, "black size should not be zero");

    return false;
}

} // namespace parakeet_crypto::utils
