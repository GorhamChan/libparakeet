#pragma once

#include <algorithm>
#include <array>
#include <cstdint>

namespace parakeet_crypto::kgm
{

static constexpr std::array<uint8_t, 16> kKgmHeader{0x7C, 0xD5, 0x32, 0xEB, 0x86, 0x02, 0x7F, 0x4B,
                                                    0xA8, 0xAF, 0xA6, 0x8E, 0x0F, 0xFF, 0x99, 0x14};

static constexpr std::array<uint8_t, 16> kKgmTestDataPlain{0x38, 0x85, 0xED, 0x92, 0x79, 0x5F, 0xF8, 0x4C,
                                                           0xB3, 0x03, 0x61, 0x41, 0x16, 0xA0, 0x1D, 0x47};

static constexpr std::array<uint8_t, 16> kVprHeader{0x05, 0x28, 0xBC, 0x96, 0xE9, 0xE4, 0x5A, 0x43,
                                                    0x91, 0xAA, 0xBD, 0xD0, 0x7A, 0xF5, 0x36, 0x31};

static constexpr std::array<uint8_t, 16> kVprTestDataPlain{0x1D, 0x5A, 0x05, 0x34, 0x0C, 0x41, 0x8D, 0x42,
                                                           0x9C, 0x83, 0x92, 0x6C, 0xAE, 0x16, 0xFE, 0x56};

inline bool IsKGMHeader(const uint8_t *buffer)
{
    return std::equal(kKgmHeader.begin(), kKgmHeader.end(), buffer);
}

inline bool IsKGMTestDataPlain(const uint8_t *buffer)
{
    return std::equal(kKgmTestDataPlain.begin(), kKgmTestDataPlain.end(), buffer);
}

inline bool IsVPRHeader(const uint8_t *buffer)
{
    return std::equal(kVprHeader.begin(), kVprHeader.end(), buffer);
}

inline bool IsVPRTestDataPlain(const uint8_t *buffer)
{
    return std::equal(kVprTestDataPlain.begin(), kVprTestDataPlain.end(), buffer);
}

} // namespace parakeet_crypto::kgm
