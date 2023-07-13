#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "parakeet-crypto/utils/hash/sha1.h"

#include <algorithm>
#include <array>
#include <vector>

using ::testing::ContainerEq;

using namespace parakeet_crypto::utils::hash;

// Test vector from "FIPS PUB 180-1": https://csrc.nist.gov/publications/detail/fips/180/1/archive/1995-04-17

// NOLINTBEGIN(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)

TEST(Utils_Hash_SHA1, empty_buffer)
{
    std::array<uint8_t, 0> input{};
    auto digest = sha1(input);

    std::array<uint8_t, 20> expected_hash = {0xDA, 0x39, 0xA3, 0xEE, 0x5E, 0x6B, 0x4B, 0x0D, 0x32, 0x55,
                                             0xBF, 0xEF, 0x95, 0x60, 0x18, 0x90, 0xAF, 0xD8, 0x07, 0x09};

    ASSERT_THAT(expected_hash, ContainerEq(digest));
}

// This appendix is for informational purposes only and is not required to meet the standard.
// Let the message be the ASCII binary-coded form of "abc", ...
TEST(Utils_Hash_SHA1, TestCase1_small_buffer)
{
    std::array<uint8_t, 3> input{'a', 'b', 'c'};
    auto digest = sha1(input);

    std::array<uint8_t, 20> expected_hash = {0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A, 0xBA, 0x3E,
                                             0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C, 0x9C, 0xD0, 0xD8, 0x9D};

    ASSERT_THAT(expected_hash, ContainerEq(digest));
}

// This appendix is for informational purposes only and is not required to meet the standard.
// Let the message be the binary-coded form (cf. Appendix A) of the ASCII string
//     "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
TEST(Utils_Hash_SHA1, just_56_bytes)
{
    std::string input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    auto digest = sha1(input);

    std::array<uint8_t, 20> expected_hash = {0x84, 0x98, 0x3E, 0x44, 0x1C, 0x3B, 0xD2, 0x6E, 0xBA, 0xAE,
                                             0x4A, 0xA1, 0xF9, 0x51, 0x29, 0xE5, 0xE5, 0x46, 0x70, 0xF1};

    ASSERT_THAT(expected_hash, ContainerEq(digest));
}

TEST(Utils_Hash_SHA1, just_more_than_56_bytes)
{
    std::string input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq-parakeet";
    auto digest = sha1(input);

    std::array<uint8_t, 20> expected_hash = {0x40, 0xDA, 0x9F, 0xA2, 0xCE, 0xBF, 0x08, 0x26, 0xA7, 0x8C,
                                             0x39, 0x74, 0xE0, 0x4A, 0xCF, 0x28, 0x62, 0xFA, 0x31, 0xD0};

    ASSERT_THAT(expected_hash, ContainerEq(digest));
}

// This appendix is for informational purposes only and is not required to meet the standard.
// Let the message be the binary-coded form of the ASCII string which consists of 1,000,000
// repetitions of "a".
TEST(Utils_Hash_SHA1, 1m_a)
{
    std::array<uint8_t, kSHA1DigestSize> digest{};

    std::array<uint8_t, 64> input{};
    std::fill(input.begin(), input.end(), 'a');

    sha1_ctx ctx{};
    sha1_init(&ctx);
    for (uint64_t i = 0; i < 1'000'000; i += 64)
    {
        sha1_update(&ctx, input.data(), input.size());
    }
    sha1_final(&ctx, digest.data());

    std::array<uint8_t, 20> expected_hash = {0x34, 0xAA, 0x97, 0x3C, 0xD4, 0xC4, 0xDA, 0xA4, 0xF6, 0x1E,
                                             0xEB, 0x2B, 0xDB, 0xAD, 0x27, 0x31, 0x65, 0x34, 0x01, 0x6F};

    ASSERT_THAT(expected_hash, ContainerEq(digest));
}

// NOLINTEND(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)
