#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "parakeet-crypto/utils/hash/hmac_sha1.h"

#include <algorithm>
#include <array>
#include <vector>

using ::testing::ContainerEq;

using namespace parakeet_crypto::utils::hash;

// NOLINTBEGIN(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)

TEST(Utils_Hash_HMAC_SHA1, hello_world)
{
    std::array<uint8_t, 0> input{};
    auto digest = hmac_sha1(std::string("hello world"), std::string("libparakeet"));

    std::array<uint8_t, kSHA1DigestSize> expected_hash = {
        0x8a, 0x8c, 0x22, 0xbf, 0x1a, 0x49, 0x29, 0x8d, 0x36, 0x1e,
        0x57, 0xc8, 0xf6, 0x17, 0x76, 0x91, 0xe2, 0xe9, 0x43, 0x78,
    };

    ASSERT_THAT(expected_hash, ContainerEq(digest));
}

// NOLINTEND(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)
