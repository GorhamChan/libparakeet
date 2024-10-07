#pragma once

#include "../../utils/endian_helper.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

namespace parakeet_crypto::cipher::aes
{

// Implementation based on tiny-AES-c: https://github.com/kokke/tiny-AES-c
// tiny-AES-c License: unlicense (public domain; http://unlicense.org/)

constexpr std::array<uint8_t, 256> sbox = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9,
    0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f,
    0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07,
    0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3,
    0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58,
    0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3,
    0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f,
    0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac,
    0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a,
    0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70,
    0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42,
    0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

constexpr auto rsbox = ([]() {
    std::array<uint8_t, 256> result{};
    for (int i = 0; i < result.size(); i++)
    {
        result[sbox[i]] = i;
    }
    return result;
})();

constexpr std::array<uint8_t, 10> kRoundConstants{0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

template <typename INT> constexpr INT rotl_cpp11(INT val, size_t n)
{
    static_assert(std::is_unsigned<INT>::value, "Rotate Left only makes sense for unsigned types");
    return (val << n) | (val >> (sizeof(INT) * CHAR_BIT - n));
}

// NOLINTBEGIN(*-magic-numbers,*-identifier-length)

// This function shifts the 4 bytes in a word to the left once.
// [a0,a1,a2,a3] becomes [a1,a2,a3,a0]
inline uint32_t RotWord(uint32_t word, size_t n = 1)
{
    if constexpr (parakeet_crypto::detail::Endian::little)
    {
        return rotl_cpp11(word, 32 - (8 * n));
    }
    else
    {
        return rotl_cpp11(word, 8 * n);
    }
}

inline uint32_t SubWord(uint32_t word)
{
    uint32_t a = sbox[word & 0xFF];
    uint32_t b = sbox[((word >> 8)) & 0xFF];
    uint32_t c = sbox[((word >> 16)) & 0xFF];
    uint32_t d = sbox[((word >> 24)) & 0xFF];
    return a | (b << 8) | (c << 16) | (d << 24);
}

inline uint32_t ApplyRoundConstant(uint32_t word, size_t round)
{
    return word ^ kRoundConstants[round - 1];
}

constexpr size_t kBlockBufferSize = 16;
template <typename T> inline void AddRoundKey(uint8_t *buf, const T &round_key, size_t round)
{

    auto key_ptr = round_key.data() + round * kBlockBufferSize;
    for (int i = 0; i < kBlockBufferSize; i++)
    {
        buf[i] ^= key_ptr[i];
    }
}

inline void SubBytes(uint8_t *buf)
{
    for (int i = 0; i < kBlockBufferSize; i++)
    {
        buf[i] = sbox[buf[i]];
    }
}

inline void InvSubBytes(uint8_t *buf)
{
    for (int i = 0; i < kBlockBufferSize; i++)
    {
        buf[i] = rsbox[buf[i]];
    }
}

inline void ShiftRow(uint8_t *buf, size_t shift_count)
{

    uint32_t value = buf[0x00]             //
                     | (buf[0x04] << 0x08) //
                     | (buf[0x08] << 0x10) //
                     | (buf[0x0C] << 0x18);

    value = RotWord(value, shift_count);

    buf[0x00] = value;
    buf[0x04] = value >> 0x08;
    buf[0x08] = value >> 0x10;
    buf[0x0C] = value >> 0x18;
}

inline void ShiftRows(uint8_t *buf)
{
    ShiftRow(&buf[1], 1);
    ShiftRow(&buf[2], 2);
    ShiftRow(&buf[3], 3);
}

inline void InvShiftRows(uint8_t *buf)
{
    ShiftRow(&buf[1], 3);
    ShiftRow(&buf[2], 2);
    ShiftRow(&buf[3], 1);
}

inline uint8_t xtime(uint8_t x)
{
    return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

inline void MixColumns(uint8_t *buf)
{
    for (int i = 0; i < 4; i++, buf += 4)
    {
        uint8_t tmp1 = buf[0];
        uint8_t tmp2 = buf[0] ^ buf[1] ^ buf[2] ^ buf[3];
        uint8_t tmp3 = buf[0] ^ buf[1];

        tmp3 = xtime(tmp3);
        buf[0] ^= tmp3 ^ tmp2;

        tmp3 = buf[1] ^ buf[2];
        tmp3 = xtime(tmp3);
        buf[1] ^= tmp3 ^ tmp2;

        tmp3 = buf[2] ^ buf[3];
        tmp3 = xtime(tmp3);
        buf[2] ^= tmp3 ^ tmp2;

        tmp3 = buf[3] ^ tmp1;
        tmp3 = xtime(tmp3);
        buf[3] ^= tmp3 ^ tmp2;
    }
}

inline uint8_t Multiply(uint8_t x, uint8_t y)
{
    return (((y & 1) * x) ^ ((y >> 1 & 1) * xtime(x)) ^ ((y >> 2 & 1) * xtime(xtime(x))) ^
            ((y >> 3 & 1) * xtime(xtime(xtime(x)))) ^
            ((y >> 4 & 1) * xtime(xtime(xtime(xtime(x)))))); /* this last call to xtime() can be omitted */
}

inline void InvMixColumns(uint8_t *buf)
{
    for (size_t i = 0; i < 4; i++, buf += 4)
    {
        uint8_t a = buf[0];
        uint8_t b = buf[1];
        uint8_t c = buf[2];
        uint8_t d = buf[3];

        buf[0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
        buf[1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
        buf[2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
        buf[3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
    }
}

// NOLINTEND(*-magic-numbers,*-identifier-length)

}; // namespace parakeet_crypto::cipher::aes