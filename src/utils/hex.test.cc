#include <cstdint>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "parakeet-crypto/utils/hex.h"

#include <algorithm>
#include <array>
#include <vector>

using namespace parakeet_crypto;
using ::testing::ContainerEq;

// NOLINTBEGIN(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)

// NOLINTBEGIN(*-reinterpret-cast)
TEST(hex, Hex)
{
    ASSERT_STREQ(utils::Hex(reinterpret_cast<const uint8_t *>("\x12\x34\x56\xab\x0f"), 5, false).c_str(), "123456ab0f");
}

TEST(hex, UnHex)
{
    ASSERT_THAT(utils::UnHex("123456ab0f"), ContainerEq(std::vector<uint8_t>{0x12, 0x34, 0x56, 0xab, 0x0f}));
    ASSERT_THAT(utils::UnHex("0x12, 0x34, not hex, then FE cD Cb 00 07 9"),
                ContainerEq(std::vector<uint8_t>{0x12, 0x34, 0xFE, 0xcd, 0xcb, 0x00, 0x07}));
}

TEST(hex, IntToFixedWidthHexString)
{
    ASSERT_STREQ(utils::IntToFixedWidthHexString(int8_t(0x34)).c_str(), "34");
    ASSERT_STREQ(utils::IntToFixedWidthHexString(int16_t(0x1234)).c_str(), "1234");
    ASSERT_STREQ(utils::IntToFixedWidthHexString(int32_t(0x1234)).c_str(), "00001234");
    ASSERT_STREQ(utils::IntToFixedWidthHexString(int64_t(0x1234)).c_str(), "0000000000001234");

    ASSERT_STREQ(utils::IntToFixedWidthHexString(int8_t(UINT8_MAX)).c_str(), "ff");
    ASSERT_STREQ(utils::IntToFixedWidthHexString(int16_t(UINT16_MAX)).c_str(), "ffff");
    ASSERT_STREQ(utils::IntToFixedWidthHexString(int32_t(UINT32_MAX)).c_str(), "ffffffff");
    ASSERT_STREQ(utils::IntToFixedWidthHexString(int64_t(UINT64_MAX)).c_str(), "ffffffffffffffff");
}

TEST(hex, IntToHexString)
{
    ASSERT_STREQ(utils::IntToHexString(int8_t(0x32)).c_str(), "32");
    ASSERT_STREQ(utils::IntToHexString(int16_t(0x123)).c_str(), "123");
    ASSERT_STREQ(utils::IntToHexString(int32_t(0x12345)).c_str(), "12345");
    ASSERT_STREQ(utils::IntToHexString(int64_t(0x76543a), false).c_str(), "76543a");

    ASSERT_STREQ(utils::IntToHexString(int8_t(-1)).c_str(), "ff");
    ASSERT_STREQ(utils::IntToHexString(int16_t(-1)).c_str(), "ffff");
    ASSERT_STREQ(utils::IntToHexString(int32_t(-1)).c_str(), "ffffffff");
    ASSERT_STREQ(utils::IntToHexString(int64_t(-1)).c_str(), "ffffffffffffffff");
}

// NOLINTEND(*-reinterpret-cast)
// NOLINTEND(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)
