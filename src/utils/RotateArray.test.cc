#include "RotateArray.h"
#include "utils/RotateArray.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <vector>

using ::testing::ContainerEq;

using namespace parakeet_crypto;

// NOLINTBEGIN(*-magic-numbers)

TEST(Utils_RotateArray, RotateLeft)
{
    uint8_t array_input[] = {'a', 'b', 'c', 'd', 'e', 'f'};
    uint8_t array_expected[] = {'c', 'd', 'e', 'f', 'a', 'b'};
    utils::RotateLeft<6, 2>(&array_input[0]);
    ASSERT_THAT(array_input, ContainerEq(array_expected));
}

// NOLINTEND(*-magic-numbers)
