#include <parakeet-crypto/xmly/scramble_key.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using ::testing::ElementsAreArray;

// NOLINTBEGIN(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)

TEST(Ximalaya, ScrambleTable)
{
    auto result = parakeet_crypto::xmly::CreateScrambleKey(0.334455, 3.998877, 5);
    ASSERT_TRUE(result.has_value());

    if (result.has_value())
    {
        std::array<uint16_t, 5> expected = {1, 3, 2, 4, 0};
        ASSERT_THAT(*result, ElementsAreArray(expected));
    }
}

TEST(Ximalaya, ScrambleTableShouldRejectInvalidValues1)
{
    auto result = parakeet_crypto::xmly::CreateScrambleKey(2.11, 3.88, 5);
    ASSERT_FALSE(result.has_value());
}

TEST(Ximalaya, ScrambleTableShouldRejectInvalidValues2)
{
    auto result = parakeet_crypto::xmly::CreateScrambleKey(0.50, 9.22, 5);
    ASSERT_FALSE(result.has_value());
}

// NOLINTEND(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)
