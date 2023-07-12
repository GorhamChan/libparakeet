#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "parakeet-crypto/utils/hash/md5.h"

#include <algorithm>
#include <array>
#include <vector>

using ::testing::ContainerEq;

using namespace parakeet_crypto::utils::hash;

// Test vector from "FIPS PUB 180-1": https://www.nist.gov/itl/ssd/software-quality-group/nsrl-test-data

// NOLINTBEGIN(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)

TEST(Utils_Hash_MD5, empty_buffer)
{
    std::array<uint8_t, 0> input{};
    auto digest = md5(input);

    std::array<uint8_t, kMD5DigestSize> expected_hash = {0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
                                                         0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e};

    ASSERT_THAT(expected_hash, ContainerEq(digest));
}

// This appendix is for informational purposes only and is not required to meet the standard.
// Let the message be the ASCII binary-coded form of "abc", ...
TEST(Utils_Hash_MD5, TestCase1_small_buffer)
{
    std::array<uint8_t, 3> input{'a', 'b', 'c'};
    auto digest = md5(input);

    std::array<uint8_t, kMD5DigestSize> expected_hash = {0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0,
                                                         0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72};

    ASSERT_THAT(expected_hash, ContainerEq(digest));
}

// This appendix is for informational purposes only and is not required to meet the standard.
// Let the message be the binary-coded form (cf. Appendix A) of the ASCII string
//     "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
TEST(Utils_Hash_MD5, just_56_bytes)
{
    std::string input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    auto digest = md5(input);

    std::array<uint8_t, kMD5DigestSize> expected_hash = {0x82, 0x15, 0xef, 0x07, 0x96, 0xa2, 0x0b, 0xca,
                                                         0xaa, 0xe1, 0x16, 0xd3, 0x87, 0x6c, 0x66, 0x4a};

    ASSERT_THAT(expected_hash, ContainerEq(digest));
}

TEST(Utils_Hash_MD5, just_more_than_56_bytes)
{
    std::string input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq-parakeet";
    auto digest = md5(input);

    std::array<uint8_t, kMD5DigestSize> expected_hash = {0xa1, 0x1c, 0x4d, 0x9a, 0x8a, 0x41, 0x7b, 0xce,
                                                         0x14, 0x4a, 0x22, 0x99, 0xad, 0x0c, 0x82, 0xcf};

    ASSERT_THAT(expected_hash, ContainerEq(digest));
}

// This appendix is for informational purposes only and is not required to meet the standard.
// Let the message be the binary-coded form of the ASCII string which consists of 1,000,000
// repetitions of "a".
TEST(Utils_Hash_MD5, 1m_a)
{
    std::array<uint8_t, kMD5DigestSize> digest{};

    std::array<uint8_t, 64> input{};
    std::fill(input.begin(), input.end(), 'a');

    md5_ctx ctx{};
    md5_init(&ctx);
    for (uint64_t i = 0; i < 1'000'000; i += 64)
    {
        md5_update(&ctx, input.data(), input.size());
    }
    md5_final(&ctx, digest.data());

    std::array<uint8_t, kMD5DigestSize> expected_hash = {0x77, 0x07, 0xD6, 0xAE, 0x4E, 0x02, 0x7C, 0x70,
                                                         0xEE, 0xA2, 0xA9, 0x35, 0xC2, 0x29, 0x6F, 0x21};

    ASSERT_THAT(expected_hash, ContainerEq(digest));
}

// NOLINTEND(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)
