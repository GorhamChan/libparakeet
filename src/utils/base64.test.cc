#include <cstdint>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "parakeet-crypto/utils/base64.h"

#include <algorithm>
#include <array>
#include <vector>

using ::testing::ContainerEq;

using namespace parakeet_crypto;

// NOLINTBEGIN(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)

TEST(base64, HappyPath)
{
    std::vector<uint8_t> expected({'l', 'i', 'b', 'p', 'a', 'r', 'a', 'k', 'e', 'e', 't'});
    ASSERT_THAT(utils::Base64Decode(std::string("bGlicGFyYWtlZXQ=")), ContainerEq(expected));
    ASSERT_THAT(utils::Base64Decode(std::string("bGlicGFyYWtlZXQ")), ContainerEq(expected));
    ASSERT_THAT(utils::Base64Decode(std::string("bGli")), ContainerEq(std::vector<uint8_t>{'l', 'i', 'b'}));
}

TEST(base64, UrlSafeDecode)
{
    std::vector<uint8_t> expected({0x6b, 0xef, 0xf4, 0xff});
    ASSERT_THAT(utils::Base64Decode(std::string("a-_0_-")), ContainerEq(expected));
    ASSERT_THAT(utils::Base64Decode(std::string("a-_0_-==")), ContainerEq(expected));
}

TEST(base64, encode_buffer_len)
{
    ASSERT_EQ(utils::base64_impl::b64_encode_buffer_len(0), 1);
    ASSERT_EQ(utils::base64_impl::b64_encode_buffer_len(1), 5);
    ASSERT_EQ(utils::base64_impl::b64_encode_buffer_len(2), 5);
    ASSERT_EQ(utils::base64_impl::b64_encode_buffer_len(3), 5);
    ASSERT_EQ(utils::base64_impl::b64_encode_buffer_len(4), 9);
    ASSERT_EQ(utils::base64_impl::b64_encode_buffer_len(5), 9);
    ASSERT_EQ(utils::base64_impl::b64_encode_buffer_len(6), 9);
    ASSERT_EQ(utils::base64_impl::b64_encode_buffer_len(7), 13);
    ASSERT_EQ(utils::base64_impl::b64_encode_buffer_len(8), 13);
}

TEST(base64, decode_buffer_len)
{
    ASSERT_EQ(utils::base64_impl::b64_decode_buffer_len(0), 0);
    ASSERT_EQ(utils::base64_impl::b64_decode_buffer_len(1), 3);
    ASSERT_EQ(utils::base64_impl::b64_decode_buffer_len(2), 3);
    ASSERT_EQ(utils::base64_impl::b64_decode_buffer_len(3), 3);
    ASSERT_EQ(utils::base64_impl::b64_decode_buffer_len(4), 3);
    ASSERT_EQ(utils::base64_impl::b64_decode_buffer_len(5), 6);
    ASSERT_EQ(utils::base64_impl::b64_decode_buffer_len(6), 6);
    ASSERT_EQ(utils::base64_impl::b64_decode_buffer_len(7), 6);
    ASSERT_EQ(utils::base64_impl::b64_decode_buffer_len(8), 6);
}

// NOLINTEND(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)
