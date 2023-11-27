#include <cstdint>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "parakeet-crypto/utils/hex.h"

#include <algorithm>
#include <array>
#include <vector>

using namespace parakeet_crypto;

// NOLINTBEGIN(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)

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

// NOLINTEND(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)
