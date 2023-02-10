#include "rotate_array.h"
#include "utils/rotate_array.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <vector>

using ::testing::ContainerEq;

using namespace parakeet_crypto;

// NOLINTBEGIN(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)

TEST(Utils_RotateArray, RotateLeft)
{
    uint8_t array_input[] = {'a', 'b', 'c', 'd', 'e', 'f'};
    uint8_t array_expected[] = {'c', 'd', 'e', 'f', 'a', 'b'};
    utils::RotateLeft(&array_input[0], 6, 2);
    ASSERT_THAT(array_input, ContainerEq(array_expected));
}

// NOLINTEND(*-magic-numbers,cppcoreguidelines-avoid-non-const-global-variables,cppcoreguidelines-owning-memory)
