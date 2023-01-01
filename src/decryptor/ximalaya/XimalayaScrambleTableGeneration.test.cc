#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <random>
#include <vector>

#include "XimalayaScrambleTableGeneration.h"
#include "test/helper.test.hh"

using ::testing::ElementsAreArray;

using namespace parakeet_crypto::decryptor::ximalaya;
using namespace parakeet_crypto;

TEST(Ximalaya, ScrambleTable) {
    std::array<uint16_t, 5> result;
    GenerateScrambleTable(result, 0.334455, 3.998877);

    auto expected = std::to_array<uint16_t>({1, 3, 2, 4, 0});
    ASSERT_THAT(result, ElementsAreArray(expected));
}
