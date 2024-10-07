#include <cstdint>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "qingting_fm.h"

#include <algorithm>
#include <array>
#include <vector>

using namespace parakeet_crypto::qtfm;
using testing::ContainerEq;

// NOLINTBEGIN(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)

TEST(QingTingFM, crypto_key_rfc)
{
    DeviceSecretKey expected = {0x4c, 0x43, 0x18, 0xd9, 0x98, 0xe6, 0xef, 0x57,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34};
    auto actual = CreateCryptoIV(".p!MTIzNDU2.qta", 0x12345); // "123456"
    ASSERT_THAT(actual, ContainerEq(expected));
}

TEST(QingTingFM, crypto_key_digit_id)
{
    DeviceSecretKey expected = {0x32, 0xef, 0xa8, 0xef, 0x16, 0xc4, 0x98, 0x33,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x56, 0x78};
    auto actual = CreateCryptoIV(".p!OTg3NjU0MzIx.qta", 0x456789); // "987654321"
    ASSERT_THAT(actual, ContainerEq(expected));
}

TEST(QingTingFM, crypto_key_url_safe)
{
    DeviceSecretKey expected = {0x2e, 0x08, 0x09, 0x99, 0x62, 0x7a, 0xea, 0xac,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54, 0x32};
    auto actual = CreateCryptoIV(".p~!MTIzNEA-_1==.qta", 0x54321); // "1234@\3e\xff"
    ASSERT_THAT(actual, ContainerEq(expected));
}

// NOLINTEND(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)
