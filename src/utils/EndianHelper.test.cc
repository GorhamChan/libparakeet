#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "EndianHelper.h"

#include <array>
#include <ranges>

using ::testing::ContainerEq;

using namespace parakeet_crypto;

// NOLINTBEGIN(*-magic-numbers)

TEST(EndianHelper, ReadData) {
    static auto kTestData = std::to_array<uint8_t>({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0});

    auto expected_le = uint32_t{0x04030201};
    auto expected_be = uint64_t{0x0102030405060708};
    auto actual_le = ReadLittleEndian<uint32_t>(&kTestData[1]);
    auto actual_be = ReadBigEndian<uint64_t>(&kTestData[1]);

    ASSERT_EQ(actual_le, expected_le);
    ASSERT_EQ(actual_be, expected_be);
}

TEST(EndianHelper, WriteData) {
    std::array<uint8_t, 0x20> test_array_le{};
    std::array<uint8_t, 0x20> test_array_be{};
    std::ranges::fill(test_array_le, uint8_t{0xff});
    std::ranges::fill(test_array_be, uint8_t{0xdd});

    std::array<uint8_t, 0x20> expected_array_le{
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  // 0x00
        0xff, 0x01, 0x02, 0x03, 0x04, 0xff, 0xff, 0xff,  // 0x08
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  // 0x10
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  // 0x18
    };
    std::array<uint8_t, 0x20> expected_array_be{
        0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,  // 0x00
        0xdd, 0xdd, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,  // 0x08
        0x07, 0x08, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,  // 0x10
        0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd,  // 0x18
    };

    WriteLittleEndian(&test_array_le[0x09], uint32_t{0x04030201});
    WriteBigEndian(&test_array_be[0x0A], uint64_t{0x0102030405060708});

    ASSERT_THAT(test_array_be, ContainerEq(expected_array_be));
    ASSERT_THAT(test_array_le, ContainerEq(expected_array_le));
}

// NOLINTEND(*-magic-numbers)
